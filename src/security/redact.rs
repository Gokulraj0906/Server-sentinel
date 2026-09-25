//! Secret redaction for command lines and captured file content.
//!
//! Recording what people type is the point of the product — but people
//! type passwords into command lines (`mysql -pS3cret`, `curl -u
//! admin:hunter2`, `export API_KEY=...`) and configs hold credentials.
//! Storing those verbatim would turn the audit database into the most
//! valuable file on the box. Everything captured passes through here
//! first (on by default; `security.redact_secrets = false` to disable).

use regex::Regex;

pub struct Redactor {
    rules: Vec<(Regex, &'static str)>,
    enabled: bool,
}

impl Redactor {
    pub fn new(enabled: bool) -> Self {
        let rules = [
            // key=value / key: value (commands, env vars, config files)
            (
                r#"(?i)\b((?:[a-z0-9_]*_)?(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret))(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"',;]+)"#,
                "$1$2***",
            ),
            // --password VALUE: whitespace-separated form only for flags, so
            // prose like `git commit -m "fix token refresh"` is left alone
            (
                r#"(?i)(\s--?(?:[a-z0-9]+[-_])?(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|client[-_]?secret))(\s+)("[^"]*"|'[^']*'|[^\s"'-][^\s"']*)"#,
                "$1$2***",
            ),
            // scheme://user:password@host
            (r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@", "${1}***@"),
            // Authorization headers
            (r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)\S+", "${1}***"),
            (r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}", "${1}***"),
            // mysql -pSECRET (no-space form; scoped to the MySQL client
            // family so `find -print` etc. are left alone)
            (r"(\b(?:mysql|mysqldump|mariadb|mysqladmin)\b[^\n]*?\s-p)(\S+)", "${1}***"),
            // curl -u user:pass / --user user:pass
            (r"(\s(?:-u|--user)\s+[^\s:]+:)\S+", "${1}***"),
            // sshpass -p pass
            (r"(\bsshpass\s+-p\s*)\S+", "${1}***"),
            // Well-known token formats anywhere
            (r"\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}", "${1}_***"),
            (r"\bAKIA[0-9A-Z]{16}\b", "AKIA***"),
            (r"\bxox[abpr]-[A-Za-z0-9-]{10,}", "xox?-***"),
            (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "-----PRIVATE KEY REDACTED-----"),
        ];
        Self {
            rules: rules
                .into_iter()
                .map(|(re, rep)| (Regex::new(re).expect("static redaction regex"), rep))
                .collect(),
            enabled,
        }
    }

    pub fn redact(&self, input: &str) -> String {
        if !self.enabled {
            return input.to_string();
        }
        let mut out = input.to_string();
        for (re, rep) in &self.rules {
            if re.is_match(&out) {
                out = re.replace_all(&out, *rep).into_owned();
            }
        }
        out
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secret_shapes() {
        let r = Redactor::new(true);
        let cases = [
            ("mysql -u root -pS3cretPass db", "mysql -u root -p*** db"),
            ("export API_KEY=abcd1234", "export API_KEY=***"),
            ("app --password hunter2 --port 80", "app --password *** --port 80"),
            ("DB_PASSWORD='p@ss w0rd' ./run", "DB_PASSWORD=*** ./run"),
            ("curl -u admin:hunter2 https://x", "curl -u admin:*** https://x"),
            ("git clone https://bob:tok3n@github.com/x/y", "git clone https://bob:***@github.com/x/y"),
            ("curl -H 'Authorization: Bearer eyJhbGciOi.xyz' u", "curl -H 'Authorization: Bearer *** u"),
            ("sshpass -p secret ssh host", "sshpass -p *** ssh host"),
            ("echo ghp_abcdefghijklmnopqrstuvwxyz0123", "echo ghp_***"),
        ];
        for (input, expected) in cases {
            assert_eq!(r.redact(input), expected, "input: {input}");
        }
    }

    #[test]
    fn leaves_ordinary_commands_alone() {
        let r = Redactor::new(true);
        for cmd in [
            "vim /etc/nginx/nginx.conf",
            "systemctl restart nginx",
            "ls -la /var/log",
            "ps -p 1234",
            "tar -xzf backup.tar.gz",
            "find / -name x -print",
            "cd /tmp && pwd && ls",
            "git commit -m fix token refresh",
            "kubectl get secret -n prod",
            "tail -f /var/log/auth.log",
        ] {
            assert_eq!(r.redact(cmd), cmd);
        }
        assert_eq!(Redactor::new(false).redact("mysql -pX"), "mysql -pX");
    }

    #[test]
    fn redacts_config_file_content() {
        let r = Redactor::new(true);
        let cfg = "host = db1\npassword = hunter2\nport = 5432\n";
        assert_eq!(r.redact(cfg), "host = db1\npassword = ***\nport = 5432\n");
    }
}
