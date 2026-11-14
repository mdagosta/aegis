//! The route tables, as plain data: every request either parses into one of these variants or is
//! refused. Handlers live in `server`; keeping the table here makes "what can each socket do" one
//! screen to review.
//!
//! Scope names contain `/`, so the scope is everything between `/v1/scope/` and the `/key/{key}` that
//! ends the path (before an optional action). Keys never contain `/`, which makes the split unambiguous.
//! Paths are matched as sent: names can't contain `%`, so nothing is percent-decoded.

use axum::http::Method;

use crate::names::{KeyName, NameError, ScopeName};

/// Everything `read.sock` serves.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadRoute {
    /// `GET /v1/scope/{scope}`: the scope's values, if the caller's uid may read it.
    Fetch(ScopeName),
}

/// Everything `admin.sock` serves. No variant returns a value.
#[derive(Debug, PartialEq, Eq)]
pub enum AdminRoute {
    /// `GET /v1/scopes`: every scope and key, current version metadata.
    ListScopes,
    /// `GET /v1/scope/{scope}/key/{key}/versions`: version history, metadata only.
    Versions(ScopeName, KeyName),
    /// `PUT /v1/scope/{scope}/key/{key}` `{"value": "..."}`: a new version.
    Set(ScopeName, KeyName),
    /// `DELETE /v1/scope/{scope}/key/{key}`: a tombstone version.
    Delete(ScopeName, KeyName),
    /// `POST /v1/scope/{scope}/key/{key}/rollback` `{"version": n}`.
    Rollback(ScopeName, KeyName),
    /// `POST /v1/scope/{scope}/key/{key}/generate` `{"bytes": 32}`: a random value, never returned.
    Generate(ScopeName, KeyName),
    /// `GET /v1/audit?limit=n`: recent audit rows.
    Audit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RouteError {
    NotFound,
    MethodNotAllowed,
    BadName(NameError),
}

impl From<NameError> for RouteError {
    fn from(e: NameError) -> Self {
        RouteError::BadName(e)
    }
}

const SCOPE_PREFIX: &str = "/v1/scope/";

pub fn parse_read(method: &Method, path: &str) -> Result<ReadRoute, RouteError> {
    let scope = path
        .strip_prefix(SCOPE_PREFIX)
        .ok_or(RouteError::NotFound)?;
    if method != Method::GET {
        return Err(RouteError::MethodNotAllowed);
    }
    Ok(ReadRoute::Fetch(ScopeName::parse(scope)?))
}

/// Split `{scope}/key/{key}` (with `suffix` segments after the key) into names.
fn scope_and_key(segments: &[&str], suffix: usize) -> Result<(ScopeName, KeyName), RouteError> {
    // At least one scope segment, then "key", then the key, then the suffix.
    if segments.len() < 3 + suffix {
        return Err(RouteError::NotFound);
    }
    let key_at = segments.len() - 1 - suffix;
    if segments[key_at - 1] != "key" {
        return Err(RouteError::NotFound);
    }
    let scope = ScopeName::parse(&segments[..key_at - 1].join("/"))?;
    let key = KeyName::parse(segments[key_at])?;
    Ok((scope, key))
}

pub fn parse_admin(method: &Method, path: &str) -> Result<AdminRoute, RouteError> {
    match path {
        "/v1/scopes" => {
            return if method == Method::GET {
                Ok(AdminRoute::ListScopes)
            } else {
                Err(RouteError::MethodNotAllowed)
            };
        }
        "/v1/audit" => {
            return if method == Method::GET {
                Ok(AdminRoute::Audit)
            } else {
                Err(RouteError::MethodNotAllowed)
            };
        }
        _ => {}
    }
    let rest = path
        .strip_prefix(SCOPE_PREFIX)
        .ok_or(RouteError::NotFound)?;
    let segments: Vec<&str> = rest.split('/').collect();
    let last = *segments.last().unwrap_or(&"");
    match *method {
        Method::GET if last == "versions" => {
            let (scope, key) = scope_and_key(&segments, 1)?;
            Ok(AdminRoute::Versions(scope, key))
        }
        Method::PUT => {
            let (scope, key) = scope_and_key(&segments, 0)?;
            Ok(AdminRoute::Set(scope, key))
        }
        Method::DELETE => {
            let (scope, key) = scope_and_key(&segments, 0)?;
            Ok(AdminRoute::Delete(scope, key))
        }
        Method::POST if last == "rollback" => {
            let (scope, key) = scope_and_key(&segments, 1)?;
            Ok(AdminRoute::Rollback(scope, key))
        }
        Method::POST if last == "generate" => {
            let (scope, key) = scope_and_key(&segments, 1)?;
            Ok(AdminRoute::Generate(scope, key))
        }
        Method::GET | Method::POST => Err(RouteError::NotFound),
        _ => Err(RouteError::MethodNotAllowed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str) -> ScopeName {
        ScopeName::parse(name).unwrap()
    }

    fn k(name: &str) -> KeyName {
        KeyName::parse(name).unwrap()
    }

    #[test]
    fn read_routes() {
        assert_eq!(
            parse_read(&Method::GET, "/v1/scope/epiphyte/prod"),
            Ok(ReadRoute::Fetch(s("epiphyte/prod")))
        );
        assert_eq!(
            parse_read(&Method::GET, "/v1/scope/a"),
            Ok(ReadRoute::Fetch(s("a")))
        );
        assert_eq!(
            parse_read(&Method::POST, "/v1/scope/a"),
            Err(RouteError::MethodNotAllowed)
        );
        for path in ["/", "/v1/scopes", "/v1/scope", "/v1/audit", "/v2/scope/a"] {
            assert_eq!(
                parse_read(&Method::GET, path),
                Err(RouteError::NotFound),
                "{path}"
            );
        }
        for path in [
            "/v1/scope/",
            "/v1/scope/a/",
            "/v1/scope/a/../b",
            "/v1/scope/a%2Fb",
            "/v1/scope/A",
            "/v1/scope//a",
        ] {
            assert!(
                matches!(parse_read(&Method::GET, path), Err(RouteError::BadName(_))),
                "{path}"
            );
        }
    }

    #[test]
    fn admin_routes() {
        let cases = [
            (Method::GET, "/v1/scopes", AdminRoute::ListScopes),
            (Method::GET, "/v1/audit", AdminRoute::Audit),
            (
                Method::GET,
                "/v1/scope/epiphyte/prod/key/DB/versions",
                AdminRoute::Versions(s("epiphyte/prod"), k("DB")),
            ),
            (
                Method::PUT,
                "/v1/scope/epiphyte/prod/key/DB",
                AdminRoute::Set(s("epiphyte/prod"), k("DB")),
            ),
            (
                Method::DELETE,
                "/v1/scope/a/key/DB",
                AdminRoute::Delete(s("a"), k("DB")),
            ),
            (
                Method::POST,
                "/v1/scope/a/b/c/key/K/rollback",
                AdminRoute::Rollback(s("a/b/c"), k("K")),
            ),
            (
                Method::POST,
                "/v1/scope/a/key/K/generate",
                AdminRoute::Generate(s("a"), k("K")),
            ),
            // Scope segments and keys that look like route words.
            (
                Method::PUT,
                "/v1/scope/x/key/y/key/versions",
                AdminRoute::Set(s("x/key/y"), k("versions")),
            ),
            (
                Method::GET,
                "/v1/scope/key/key/key/versions",
                AdminRoute::Versions(s("key"), k("key")),
            ),
            (
                Method::POST,
                "/v1/scope/rollback/key/generate/generate",
                AdminRoute::Generate(s("rollback"), k("generate")),
            ),
        ];
        for (method, path, route) in cases {
            assert_eq!(parse_admin(&method, path), Ok(route), "{method} {path}");
        }
    }

    #[test]
    fn admin_refusals() {
        let not_found = [
            (Method::GET, "/"),
            (Method::GET, "/v1/scope/a"),
            (Method::GET, "/v1/scope/a/key/K"),
            (Method::GET, "/v1/scope/a/key/K/value"),
            (Method::GET, "/v1/scope/epiphyte/prod"),
            (Method::POST, "/v1/scope/a/key/K"),
            (Method::POST, "/v1/scope/a/key/K/reveal"),
            (Method::PUT, "/v1/scope/a"),
            (Method::PUT, "/v1/scope/key/K"),
            (Method::PUT, "/v1/scope/a/K"),
            (Method::DELETE, "/v1/scope/a/key/K/versions"),
            (Method::GET, "/v1/scopes/"),
        ];
        for (method, path) in not_found {
            assert_eq!(
                parse_admin(&method, path),
                Err(RouteError::NotFound),
                "{method} {path}"
            );
        }
        let not_allowed = [
            (Method::POST, "/v1/scopes"),
            (Method::DELETE, "/v1/audit"),
            (Method::PATCH, "/v1/scope/a/key/K"),
            (Method::HEAD, "/v1/scope/a/key/K/versions"),
        ];
        for (method, path) in not_allowed {
            assert_eq!(
                parse_admin(&method, path),
                Err(RouteError::MethodNotAllowed),
                "{method} {path}"
            );
        }
        for path in [
            "/v1/scope//key/K",
            "/v1/scope/a/key/",
            "/v1/scope/a/key/K.%41",
            "/v1/scope/a/key/..",
            "/v1/scope/A/key/K",
        ] {
            assert!(
                matches!(parse_admin(&Method::PUT, path), Err(RouteError::BadName(_))),
                "{path}"
            );
        }
    }
}
