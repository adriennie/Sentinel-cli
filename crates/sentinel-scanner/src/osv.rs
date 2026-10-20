use crate::{bounded_read, digest, Advisory, Package, ScanError, Severity, MAX_INPUT_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Inject a fake client for reproducible tests. Errors never contain response bodies.
pub trait OsvClient: Sync {
    fn query(&self, package: &Package) -> Result<Vec<Advisory>, ScanError>;
}
pub struct HttpOsv {
    client: reqwest::blocking::Client,
    endpoint: String,
}
impl HttpOsv {
    pub fn new() -> Result<Self, ScanError> {
        Self::with_endpoint("https://api.osv.dev/v1/query")
    }
    fn with_endpoint(endpoint: &str) -> Result<Self, ScanError> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("sentinel/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ScanError("Unable to initialize OSV HTTP client"))?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
        })
    }
}
fn valid_advisories(advisories: &[Advisory]) -> bool {
    advisories.len() <= 10_000
        && advisories.iter().all(|a| {
            !a.id.is_empty()
                && a.id.len() <= 128
                && a.id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:.".contains(&b))
        })
}
fn advisory_kind(value: &Value) -> crate::AdvisoryKind {
    let informational = value.pointer("/database_specific/informational");
    if informational.is_some_and(|v| {
        v.as_str() == Some("unmaintained")
            || v.as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("unmaintained")))
    }) {
        crate::AdvisoryKind::Maintenance
    } else {
        crate::AdvisoryKind::Unknown
    }
}
fn severity(value: &Value, package: &Package) -> Severity {
    let mut levels = Vec::new();
    let mut collect_vectors = |value: &Value| {
        if let Some(entries) = value.get("severity").and_then(Value::as_array) {
            for entry in entries {
                if entry.get("type").and_then(Value::as_str) == Some("CVSS_V3") {
                    if let Some(score) = entry
                        .get("score")
                        .and_then(Value::as_str)
                        .and_then(|vector| vector.parse::<cvss::v3::Base>().ok())
                        .map(|vector| vector.score().value())
                    {
                        levels.push(if score >= 9.0 {
                            Severity::Critical
                        } else if score >= 7.0 {
                            Severity::High
                        } else if score >= 4.0 {
                            Severity::Medium
                        } else {
                            Severity::Low
                        });
                    }
                }
            }
        }
    };
    collect_vectors(value);
    if let Some(affected) = value.get("affected").and_then(Value::as_array) {
        for entry in affected {
            if entry.pointer("/package/name").and_then(Value::as_str) == Some(&package.name)
                && entry.pointer("/package/ecosystem").and_then(Value::as_str)
                    == Some(&package.ecosystem)
            {
                collect_vectors(entry);
            }
        }
    }
    if let Some(s) = value
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
        .and_then(Severity::parse)
    {
        levels.push(s);
    }
    if let Some(affected) = value.get("affected").and_then(Value::as_array) {
        for affected in affected {
            if affected.pointer("/package/name").and_then(Value::as_str) == Some(&package.name)
                && affected
                    .pointer("/package/ecosystem")
                    .and_then(Value::as_str)
                    == Some(&package.ecosystem)
            {
                if let Some(s) = affected
                    .pointer("/ecosystem_specific/severity")
                    .and_then(Value::as_str)
                    .and_then(Severity::parse)
                {
                    levels.push(s);
                }
            }
        }
    }
    levels.into_iter().max().unwrap_or(Severity::Unknown)
}
impl OsvClient for HttpOsv {
    fn query(&self, package: &Package) -> Result<Vec<Advisory>, ScanError> {
        package.validate()?;
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut token = None;
        let mut seen = BTreeSet::new();
        let mut advisories = Vec::new();
        for _ in 0..20 {
            let mut request = json!({"package":{"name":package.name,"ecosystem":package.ecosystem},"version":package.version});
            if let Some(token) = &token {
                request["page_token"] = json!(token);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(ScanError("OSV query time budget exhausted"))?;
            let response = self
                .client
                .post(&self.endpoint)
                .timeout(remaining)
                .json(&request)
                .send()
                .map_err(|_| ScanError("OSV request failed or timed out"))?;
            if !response.status().is_success() {
                return Err(ScanError("OSV returned an unsuccessful HTTP status"));
            }
            let mut bytes = Vec::new();
            response
                .take(MAX_INPUT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ScanError("Unable to read OSV response"))?;
            if bytes.len() as u64 > MAX_INPUT_BYTES {
                return Err(ScanError("OSV response exceeds size limit"));
            }
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| ScanError("Invalid OSV JSON response"))?;
            if !value.is_object() || value.get("error").is_some() {
                return Err(ScanError("Invalid OSV response shape"));
            }
            if let Some(vulns) = value.get("vulns") {
                for vulnerability in vulns
                    .as_array()
                    .ok_or(ScanError("Invalid OSV advisory list"))?
                {
                    if vulnerability.get("withdrawn").is_some_and(|v| !v.is_null()) {
                        continue;
                    }
                    let id = vulnerability
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or(ScanError("OSV advisory missing identifier"))?;
                    advisories.push(Advisory {
                        kind: advisory_kind(vulnerability),
                        id: id.into(),
                        severity: severity(vulnerability, package),
                    });
                    if advisories.len() > 10_000
                        || !advisories.last().is_some_and(|advisory| {
                            valid_advisories(std::slice::from_ref(advisory))
                        })
                    {
                        return Err(ScanError("Invalid or excessive OSV advisory data"));
                    }
                }
            }
            let next = match value.get("next_page_token") {
                Some(Value::String(value)) if !value.is_empty() && value.len() <= 4096 => {
                    Some(value.clone())
                }
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if value.is_empty() => None,
                _ => return Err(ScanError("Invalid OSV pagination token")),
            };
            match next {
                None => {
                    advisories.sort_by(|a, b| a.id.cmp(&b.id).then(b.severity.cmp(&a.severity)));
                    advisories.dedup_by(|a, b| a.id == b.id);
                    return Ok(advisories);
                }
                Some(next) => {
                    if !seen.insert(next.clone()) {
                        return Err(ScanError("Repeated OSV pagination token"));
                    }
                    token = Some(next);
                }
            }
        }
        Err(ScanError("OSV pagination limit exceeded"))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intelligence {
    pub schema_version: u32,
    pub package: Package,
    pub fetched_at: u64,
    pub advisories: Vec<Advisory>,
}
pub(crate) fn cache_key(package: &Package) -> Result<String, ScanError> {
    let bytes = serde_json::to_vec(package).map_err(|_| ScanError("Unable to encode cache key"))?;
    Ok(digest(&bytes))
}
fn cache_dir(root: &Path, create: bool) -> Result<PathBuf, ScanError> {
    let mut path = root.to_path_buf();
    for part in [".sentinel", "cache", "osv-v1"] {
        path.push(part);
        if create && !path.exists() {
            match std::fs::create_dir(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(ScanError("Unable to create OSV cache directory")),
            }
        }
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| ScanError("OSV cache unavailable"))?;
        if !metadata.file_type().is_dir() {
            return Err(ScanError(
                "OSV cache directories must not be symlinks or files",
            ));
        }
    }
    Ok(path)
}
pub(crate) fn read_cache(
    root: &Path,
    package: &Package,
    now: u64,
) -> Result<Intelligence, ScanError> {
    let path = cache_dir(root, false)?.join(format!("{}.json", cache_key(package)?));
    let data = bounded_read(&path, MAX_INPUT_BYTES)?;
    let cached: Intelligence =
        serde_json::from_slice(&data).map_err(|_| ScanError("Malformed OSV cache record"))?;
    if cached.schema_version != 1
        || &cached.package != package
        || cached.fetched_at > now
        || !valid_advisories(&cached.advisories)
    {
        return Err(ScanError("Invalid OSV cache record"));
    }
    Ok(cached)
}
pub(crate) fn write_cache(root: &Path, value: &Intelligence) -> Result<(), ScanError> {
    let directory = cache_dir(root, true)?;
    let path = directory.join(format!("{}.json", cache_key(&value.package)?));
    let mut file = tempfile::NamedTempFile::new_in(directory)
        .map_err(|_| ScanError("Unable to create cache record"))?;
    let bytes =
        serde_json::to_vec(value).map_err(|_| ScanError("Unable to serialize cache record"))?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(ScanError("OSV cache record exceeds size limit"));
    }
    file.write_all(&bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| ScanError("Unable to write cache record"))?;
    file.persist(path)
        .map_err(|_| ScanError("Unable to persist cache record"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};
    fn serve(responses: Vec<&'static str>, run: impl FnOnce(HttpOsv)) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/query", listener.local_addr().unwrap());
        let task = thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut socket, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => {
                            panic!("Mock server did not receive expected request: {error}")
                        }
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let count = socket.read(&mut buffer).unwrap();
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let size: usize = headers
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if bytes.len() >= end + 4 + size {
                            requests
                                .push(serde_json::from_slice::<Value>(&bytes[end + 4..]).unwrap());
                            break;
                        }
                    }
                }
                if response.starts_with("HTTP/") {
                    socket.write_all(response.as_bytes()).unwrap();
                    continue;
                }
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                )
                .unwrap();
            }
            requests
        });
        run(HttpOsv::with_endpoint(&endpoint).unwrap());
        let requests = task.join().unwrap();
        assert_eq!(requests[0]["package"]["ecosystem"], "npm");
        if requests.len() > 1 {
            assert_eq!(requests[1]["page_token"], "next");
        }
    }
    fn package() -> Package {
        Package {
            ecosystem: "npm".into(),
            name: "example".into(),
            version: "1.0.0".into(),
        }
    }
    #[test]
    fn http_pagination_and_severity() {
        serve(
            vec![
                r#"{"vulns":[{"id":"GHSA-test","database_specific":{"severity":"HIGH"}}],"next_page_token":"next"}"#,
                r#"{"vulns":[{"id":"withdrawn","withdrawn":"2024-01-01"},{"id":"unknown"}]}"#,
            ],
            |client| {
                let result = client.query(&package()).unwrap();
                assert_eq!(result.len(), 2);
                assert_eq!(result[0].severity, Severity::High);
                assert_eq!(result[1].severity, Severity::Unknown);
            },
        );
    }
    #[test]
    fn malformed_http_data_is_not_clean() {
        serve(vec![r#"{"vulns":"invalid"}"#], |client| {
            assert!(client.query(&package()).is_err())
        });
        serve(
            vec![
                r#"{"vulns":[],"next_page_token":"next"}"#,
                r#"{"vulns":[],"next_page_token":"next"}"#,
            ],
            |client| assert!(client.query(&package()).is_err()),
        );
    }
    #[test]
    fn cvss_vectors_are_scored_and_missing_severity_is_unknown() {
        let value = json!({"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]});
        assert_eq!(severity(&value, &package()), Severity::Critical);
        assert_eq!(severity(&json!({}), &package()), Severity::Unknown);
        assert_eq!(
            severity(
                &json!({"severity":[{"type":"CVSS_V3","score":"invalid"}]}),
                &package()
            ),
            Severity::Unknown
        );
    }
    #[test]
    fn unsuccessful_http_status_does_not_expose_response_body() {
        serve(vec!["HTTP/1.1 429 Too Many Requests\r\nContent-Length: 23\r\nConnection: close\r\n\r\nSYNTHETIC_PRIVATE_VALUE"], |client| {
            let error = client.query(&package()).unwrap_err();
            assert!(!error.to_string().contains("SYNTHETIC_PRIVATE_VALUE"));
            assert!(error.to_string().contains("HTTP status"));
        });
    }
}

#[derive(Debug, Serialize)]
pub struct CacheInspection {
    pub packages_total: usize,
    pub packages_inspected: usize,
    pub available: usize,
    pub stale: usize,
    pub missing_or_invalid: usize,
}
/// Offline-only health inspection; bounded independently of inventory size.
pub fn inspect_cache(root: &Path, inventory: &crate::Inventory) -> CacheInspection {
    let mut report = CacheInspection {
        packages_total: inventory.packages.len(),
        packages_inspected: 0,
        available: 0,
        stale: 0,
        missing_or_invalid: 0,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|now| now.as_secs())
        .unwrap_or(0);
    for package in inventory.packages.keys().take(1000) {
        report.packages_inspected += 1;
        match read_cache(root, package, now) {
            Ok(record) => {
                report.available += 1;
                if now - record.fetched_at > crate::CACHE_TTL_SECONDS {
                    report.stale += 1;
                }
            }
            Err(_) => report.missing_or_invalid += 1,
        }
    }
    report
}
