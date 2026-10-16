//! Shared short-lived database token and diagnostic helpers.
use std::time::SystemTime;

#[derive(Clone)]
pub struct AccessToken {
    pub value: String,
    pub expires_at: SystemTime,
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("value", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub fn truncate_for_error(mut body: String) -> String {
    const LIMIT: usize = 512;
    if body.len() > LIMIT {
        let mut end = LIMIT;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        body.push_str("...");
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_debug_redacts_secret() {
        let token = AccessToken {
            value: "secret-access-token".into(),
            expires_at: SystemTime::now(),
        };
        let debug = format!("{token:?}");
        assert!(!debug.contains(&token.value));
        assert!(debug.contains("[redacted]"));
    }
}
