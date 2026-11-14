//! A small blocking HTTP/1.1 client over a Unix socket, for `aegis-vault-admin` and the tests. One
//! request per connection (`Connection: close`), so reading the response is reading to EOF.

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

/// Largest response accepted (a long audit listing is well under this).
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// Wiped on drop, since a read.sock response holds values. Best effort: reading and parsing can
    /// leave copies in freed memory. The admin CLI, the only user outside tests, never gets values.
    pub body: Zeroizing<Vec<u8>>,
}

fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

/// Send one request and read the whole response. `body`, if any, is sent as JSON.
pub fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> io::Result<Response> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", socket.display())))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let body = body.unwrap_or_default();
    let content_type = if body.is_empty() {
        ""
    } else {
        "Content-Type: application/json\r\n"
    };
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: aegis-vault\r\nConnection: close\r\n\
         {content_type}Content-Length: {}\r\n\r\n",
        body.len()
    );
    // The vault may answer before reading everything (413 for a body over its limit) and close; the
    // answer is still there to read, so a broken pipe while writing isn't the end.
    let sent = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush());
    match sent {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => return Err(e),
    }

    // Sized for any admin answer, so reading rarely reallocates (and leaves copies behind).
    let mut raw = Zeroizing::new(Vec::with_capacity(256 * 1024));
    match stream.take(MAX_RESPONSE).read_to_end(&mut raw) {
        Ok(_) => {}
        // The vault refused a body before reading all of it (413) and closed: Linux reports the reset
        // after delivering the answer, which is all there is to read.
        Err(e) if e.kind() == ErrorKind::ConnectionReset && !raw.is_empty() => {}
        Err(e) => return Err(e),
    }
    parse_response(&raw)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_response(raw: &[u8]) -> io::Result<Response> {
    let head_end = find(raw, b"\r\n\r\n").ok_or_else(|| bad("response has no end of headers"))?;
    let head =
        std::str::from_utf8(&raw[..head_end]).map_err(|_| bad("response head is not UTF-8"))?;
    let rest = &raw[head_end + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let (Some(version), Some(code)) = (parts.next(), parts.next()) else {
        return Err(bad("malformed status line"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(bad("not an HTTP/1 response"));
    }
    let status: u16 = code.parse().map_err(|_| bad("malformed status code"))?;

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(bad("malformed header"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| bad("bad Content-Length"))?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.eq_ignore_ascii_case("chunked");
        }
    }

    let body = if chunked {
        decode_chunked(rest)?
    } else if let Some(length) = content_length {
        let body = rest
            .get(..length)
            .ok_or_else(|| bad("response shorter than its Content-Length"))?;
        Zeroizing::new(body.to_vec())
    } else {
        Zeroizing::new(rest.to_vec())
    };
    Ok(Response { status, body })
}

fn decode_chunked(mut rest: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let line_end = find(rest, b"\r\n").ok_or_else(|| bad("truncated chunk size"))?;
        let line = std::str::from_utf8(&rest[..line_end]).map_err(|_| bad("bad chunk size"))?;
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| bad("bad chunk size"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        let chunk = rest.get(..size).ok_or_else(|| bad("truncated chunk"))?;
        body.extend_from_slice(chunk);
        rest = rest
            .get(size..)
            .and_then(|r| r.strip_prefix(b"\r\n"))
            .ok_or_else(|| bad("chunk not followed by CRLF"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body.as_slice(), b"{}");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n{}").is_err());
    }

    #[test]
    fn chunked_response() {
        let raw = b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body.as_slice(), b"abcde");
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab")
                .is_err()
        );
    }

    #[test]
    fn malformed_responses() {
        for raw in [
            &b"garbage"[..],
            b"HTTP/1.1\r\n\r\n",
            b"SPDY/3 200 OK\r\n\r\n",
            b"HTTP/1.1 abc OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n",
        ] {
            assert!(parse_response(raw).is_err(), "{raw:?}");
        }
    }
}
