use crate::{ScanReport, Severity};
use serde_json::{json, Value};
use std::collections::BTreeMap;
/// SARIF 2.1.0 contains redacted finding summaries, never source snippets.
pub fn sarif(report: &ScanReport, analysis: Option<&crate::AnalysisReport>) -> Value {
    let rules:BTreeMap<_,_>=report.findings.iter().map(|f|(f.rule_id,json!({"id":f.rule_id,"shortDescription":{"text":if f.package.is_some(){"Known dependency security advisory"}else{"Potential exposed credential"}},"help":{"text":f.remediation}}))).collect();
    let mut results = Vec::new();
    for f in &report.findings {
        let mut value = json!({"ruleId":f.rule_id,"level":match f.severity{Severity::Critical|Severity::High=>"error",Severity::Medium|Severity::Unknown=>"warning",Severity::Low=>"note"},"message":{"text":if f.package.is_some(){"Review the dependency advisory and upgrade to an appropriate fixed version."}else{"Potential exposed credential [REDACTED]. Remove it and rotate the credential."}},"partialFingerprints":{"sentinelFindingId/v1":f.id}});
        let mut locations = Vec::new();
        for file in &f.files {
            if file == "<sbom>" {
                continue;
            }
            let mut location = json!({"physicalLocation":{"artifactLocation":{"uri":uri(file)}}});
            if let Some(l) = &f.location {
                location["physicalLocation"]["region"] = json!({"startLine":l.line});
            }
            locations.push(location)
        }
        if !locations.is_empty() {
            value["locations"] = json!(locations)
        }
        if let Some(record) =
            analysis.and_then(|a| a.findings.iter().find(|r| r.finding_id == f.id))
        {
            value["properties"] = json!(record)
        }
        results.push(value);
    }
    let successful = report.complete && analysis.is_none_or(|a| a.complete);
    let notifications: Vec<_> = report
        .diagnostics
        .iter()
        .map(|d| json!({"level":"warning","message":{"text":d.message}}))
        .collect();
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"Sentinel","version":env!("CARGO_PKG_VERSION"),"rules":rules.into_values().collect::<Vec<_>>()}},"results":results,"invocations":[{"executionSuccessful":successful,"toolExecutionNotifications":notifications}],"properties":{"scanComplete":report.complete,"packagesChecked":report.packages_checked,"analysisComplete":analysis.map(|a|a.complete)}}]})
}
fn uri(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            out.push(b as char)
        } else {
            out.push_str(&format!("%{b:02X}"))
        }
    }
    out
}
