//! Connection limits, so a process that may open a socket can't starve everyone else.
//!
//! - Each uid may hold at most `per_uid` connections to a socket at once; a connection over that is
//!   closed as soon as it's accepted. One app (or one attacker's uid) can't use up another's share.
//! - Each socket accepts at most `total` connections at once; beyond that, new ones wait in the kernel's
//!   backlog until one closes. Keeps the vault well inside its file descriptor limit.
//! - A connection that makes no progress (reading or writing) for `idle` is closed, so a connection
//!   that never finishes its request (or never reads its answer) doesn't hold its slot forever.
//!
//! The uid is the kernel's (`SO_PEERCRED`), taken once at accept and carried with the connection.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixListener;
use tokio::net::unix::SocketAddr;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub per_uid: usize,
    pub total: usize,
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            per_uid: 16,
            total: 256,
            idle: Duration::from_secs(30),
        }
    }
}

/// Peer credentials of a connection, taken once when it's accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Peer {
    pub uid: Option<u32>,
    pub pid: Option<i32>,
}

/// A Unix listener that applies `Limits`.
pub struct LimitedListener {
    inner: UnixListener,
    limits: Limits,
    total: Arc<Semaphore>,
    /// Per-uid connection slots; `None` (no credentials) is a bucket of its own.
    per_uid: Mutex<HashMap<Option<u32>, Arc<Semaphore>>>,
}

impl LimitedListener {
    pub fn new(inner: UnixListener, limits: Limits) -> Self {
        LimitedListener {
            inner,
            limits,
            total: Arc::new(Semaphore::new(limits.total)),
            per_uid: Mutex::new(HashMap::new()),
        }
    }

    fn uid_slots(&self, uid: Option<u32>) -> Arc<Semaphore> {
        let mut map = self.per_uid.lock().unwrap_or_else(|p| p.into_inner());
        Arc::clone(
            map.entry(uid)
                .or_insert_with(|| Arc::new(Semaphore::new(self.limits.per_uid))),
        )
    }
}

impl Listener for LimitedListener {
    type Io = LimitedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let total = Arc::clone(&self.total)
                .acquire_owned()
                .await
                .expect("the semaphore is never closed");
            let (stream, addr) = match self.inner.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Typically EMFILE: back off rather than spin.
                    eprintln!("warning: accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let peer = match stream.peer_cred() {
                Ok(cred) => Peer {
                    uid: Some(cred.uid()),
                    pid: cred.pid(),
                },
                Err(_) => Peer::default(),
            };
            let Ok(uid_slot) = self.uid_slots(peer.uid).try_acquire_owned() else {
                // Over its own share: close at once. Not audited (it would let one uid flood the
                // audit table at no cost); the uid's open connections were audited when used.
                drop(stream);
                continue;
            };
            let stream = LimitedStream {
                inner: stream,
                peer,
                idle_after: self.limits.idle,
                idle: Box::pin(tokio::time::sleep(self.limits.idle)),
                _slots: (total, uid_slot),
            };
            return (stream, addr);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// An accepted connection: its peer, its slots (released on drop), and an idle timer reset on every
/// read or write that makes progress.
pub struct LimitedStream {
    inner: tokio::net::UnixStream,
    peer: Peer,
    idle_after: Duration,
    idle: Pin<Box<Sleep>>,
    _slots: (OwnedSemaphorePermit, OwnedSemaphorePermit),
}

impl LimitedStream {
    pub fn peer(&self) -> Peer {
        self.peer
    }

    /// After the inner stream answered `poll`: reset the timer on progress, or fail once it expires.
    fn watch<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match poll {
            Poll::Ready(result) => {
                let deadline = Instant::now() + self.idle_after;
                self.idle.as_mut().reset(deadline);
                Poll::Ready(result)
            }
            Poll::Pending => match self.idle.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "connection idle too long",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl AsyncRead for LimitedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.watch(cx, poll)
    }
}

impl AsyncWrite for LimitedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.watch(cx, poll)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.watch(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_flush(cx);
        this.watch(cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
