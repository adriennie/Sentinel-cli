use clap::{error::ErrorKind, Parser, Subcommand, ValueEnum};
use sentinel_core::{
    AuditCommand, AuditEventType, Project, ProjectScanOptions, ScanSelection, Severity,
};
use sentinel_policy::Level;
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Local-first security policy CLI",
    disable_colored_help = true,
    color = clap::ColorChoice::Never
)]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    project: PathBuf,
    #[arg(long, global = true, default_value = "sentinel.yml")]
    config: PathBuf,
    #[arg(long, global = true, value_enum, default_value = "text")]
    format: Format,
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,
    #[arg(short, long, global = true)]
    verbose: bool,
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum, PartialEq)]
enum Format {
    Text,
    Json,
    Sarif,
}
#[derive(Clone, Copy, ValueEnum)]
enum SecurityLevel {
    L0,
    L1,
    L2,
    L3,
}
impl From<SecurityLevel> for Level {
    fn from(value: SecurityLevel) -> Self {
        match value {
            SecurityLevel::L0 => Self::L0,
            SecurityLevel::L1 => Self::L1,
            SecurityLevel::L2 => Self::L2,
            SecurityLevel::L3 => Self::L3,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Create a version-1 project policy (does not enable runtime enforcement).
    Init {
        #[arg(long, value_enum, ignore_case = true, default_value = "L1")]
        level: SecurityLevel,
        /// Replace existing configuration.
        #[arg(long)]
        force: bool,
    },
    /// Scan configured dependencies and exposed secrets.
    Scan {
        #[arg(long = "type", value_enum)]
        scan_type: Option<ScanType>,
        /// Include ignored files in secrets scanning; hard exclusions still apply.
        #[arg(long)]
        include_ignored: bool,
        #[arg(long)]
        offline: bool,
        #[arg(long, value_parser = parse_severity, default_value = "high")]
        fail_on: Severity,
        /// Use CycloneDX JSON 1.4–1.7 instead of discovering lockfiles.
        #[arg(long)]
        sbom: Option<PathBuf>,
        /// Conservative Python import reachability prototype.
        #[arg(long)]
        reachability: bool,
        /// Add timestamped EPSS and CISA KEV intelligence.
        #[arg(long)]
        exploit_aware: bool,
        #[arg(long, requires = "reachability")]
        entrypoint: Vec<PathBuf>,
        /// Explicit distribution=module mapping for Python reachability.
        #[arg(long, requires = "reachability")]
        python_import: Vec<String>,
    },
    /// Diagnose configuration, storage, cache and supported capabilities offline.
    Doctor,
    /// Read redacted history or verify explicitly enabled integrity evidence.
    Audit {
        #[command(subcommand)]
        command: Option<AuditSubcommand>,
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=10000))]
        limit: u32,
        #[arg(long, value_parser = parse_event)]
        event: Option<AuditEventType>,
    },
    /// Install and inspect the supported Claude Code policy gate.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Launch a verified Claude session; no operating-system sandbox is provided.
    Guard {
        #[arg(long)]
        scope: Vec<String>,
        #[arg(last = true, default_value = "claude")]
        program: Vec<String>,
    },
    /// Inspect or grant exact-action, expiring approvals.
    Approvals {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    /// Run isolated synthetic policy-bypass fixtures without executing attacks.
    Redteam,
    /// Inspect project security policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}
#[derive(Subcommand)]
enum AuditSubcommand {
    /// Verify the v2 hash-chain sidecar; an independent checkpoint detects truncation.
    Verify {
        #[arg(long)]
        checkpoint: Option<PathBuf>,
    },
    /// Enable integrity and write a non-overwriting checkpoint outside the project.
    Checkpoint {
        #[arg(long)]
        output: PathBuf,
    },
}
#[derive(Subcommand)]
enum AgentCommand {
    Setup {
        #[arg(value_parser=["claude"])]
        provider: String,
    },
    Status,
    #[command(hide = true)]
    Hook,
}
#[derive(Subcommand)]
enum ApprovalCommand {
    List,
    /// Explicitly approve the original binding; changed or expired actions are rejected.
    Grant {
        id: String,
        #[arg(long)]
        binding: String,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum ScanType {
    Dependencies,
    Secrets,
}
fn parse_event(value: &str) -> Result<AuditEventType, String> {
    AuditEventType::parse(value)
        .ok_or_else(|| "Expected command.completed, policy.validated, or scan.completed".into())
}
fn parse_severity(value: &str) -> Result<Severity, String> {
    Severity::parse(value).ok_or_else(|| "Expected unknown, low, medium, high, or critical".into())
}
#[derive(Subcommand)]
enum PolicyCommand {
    /// Validate policy syntax, fields, rules, and path patterns.
    Check,
    /// Run built-in conformance tests, or JSON fixtures against the selected policy.
    Test {
        #[arg(long, conflicts_with = "changed_files")]
        fixtures: Option<PathBuf>,
        /// JSON array of proposed project-relative writes; noninteractive approvals fail closed.
        #[arg(long, conflicts_with = "fixtures")]
        changed_files: Option<PathBuf>,
    },
}
fn execute(cli: &Cli) -> Result<(String, Value, u8), sentinel_core::Error> {
    if matches!(cli.command, Command::Guard { .. }) && cli.format != Format::Text {
        return Err(sentinel_core::Error::Arguments(
            "Interactive guard requires --format text so provider output cannot corrupt JSON",
        ));
    }
    if cli.format == Format::Sarif && !matches!(cli.command, Command::Scan { .. }) {
        return Err(sentinel_core::Error::Arguments(
            "SARIF output is supported only for scan",
        ));
    }
    if matches!(
        cli.command,
        Command::Scan {
            scan_type: Some(ScanType::Secrets),
            sbom: Some(_),
            ..
        }
    ) {
        return Err(sentinel_core::Error::Arguments(
            "--sbom cannot be combined with --type secrets",
        ));
    }
    let project = match Project::resolve(&cli.project, &cli.config) {
        Ok(project) => project,
        Err(_) if matches!(cli.command, Command::Doctor) => return Ok(doctor_result(cli)),
        Err(error) => return Err(error),
    };
    if cli.verbose {
        eprintln!(
            "Project: {}\nPolicy: {}",
            project.root.display(),
            project.config.display()
        );
    }
    let result = execute_command(cli, &project);
    let command = match cli.command {
        Command::Init { .. } => AuditCommand::Init,
        Command::Policy { .. } => AuditCommand::PolicyCheck,
        Command::Scan { .. } => AuditCommand::Scan,
        Command::Audit { .. } => AuditCommand::Audit,
        Command::Doctor => AuditCommand::Doctor,
        Command::Agent { .. }
        | Command::Guard { .. }
        | Command::Approvals { .. }
        | Command::Redteam => AuditCommand::Audit,
    };
    let code = result
        .as_ref()
        .map(|(_, _, code)| *code)
        .unwrap_or_else(|error| error.exit_code() as u8);
    let packages = result.as_ref().ok().and_then(|(_, data, _)| {
        data.get("packages_checked")
            .or_else(|| data.pointer("/result/scan/packages_checked"))
            .or_else(|| data.pointer("/runs/0/properties/packagesChecked"))
            .and_then(Value::as_u64)
    });
    let findings = result.as_ref().ok().and_then(|(_, data, _)| {
        data.get("findings")
            .or_else(|| data.pointer("/result/scan/findings"))
            .or_else(|| data.pointer("/runs/0/results"))
            .and_then(Value::as_array)
            .map(|values| values.len() as u64)
    });
    let logging = project.record_command(command, code, packages, findings);
    match (result, logging) {
        (Ok((message, mut data, code)), Ok(state)) => {
            if cli.format == Format::Sarif {
                data["runs"][0]["properties"]["auditLogging"] = json!(state);
            } else {
                data["audit_logging"] = json!(state);
            }
            Ok((message, data, code))
        }
        (Ok((message, mut data, code)), Err(error)) => {
            eprintln!("warning: {error}");
            if cli.format == Format::Sarif {
                data["runs"][0]["properties"]["auditLogging"] = json!("failed");
            } else {
                data["audit_logging"] = json!("failed");
            }
            Ok((message, data, if code == 0 { 1 } else { code }))
        }
        (Err(error), logging) => {
            if let Err(audit_error) = logging {
                eprintln!("warning: {audit_error}");
            }
            Err(error)
        }
    }
}
fn doctor_result(cli: &Cli) -> (String, Value, u8) {
    let report = sentinel_core::doctor_at(&cli.project, &cli.config);
    let mut message = format!("Doctor: {}", report.status);
    for check in &report.checks {
        message.push_str(&format!(
            "\n{:?} {}: {}",
            check.status, check.id, check.message
        ));
        if check.status != sentinel_core::CheckStatus::Pass {
            message.push_str(&format!("; {}", check.remediation));
        }
    }
    (message, json!(report), report.exit_code)
}
fn execute_command(
    cli: &Cli,
    project: &Project,
) -> Result<(String, Value, u8), sentinel_core::Error> {
    match cli.command {
        Command::Doctor => Ok(doctor_result(cli)),
        Command::Agent { ref command } => {
            let result = match command {
                AgentCommand::Setup { .. } => project.agent_setup(&std::env::current_exe()?)?,
                AgentCommand::Status => project.agent_status()?,
                AgentCommand::Hook => {
                    return Err(sentinel_core::Error::Arguments(
                        "Hook callbacks use the provider protocol",
                    ))
                }
            };
            let code = if result.get("healthy") == Some(&json!(false)) {
                1
            } else {
                0
            };
            Ok((
                format!(
                    "Agent gate: {}",
                    if code == 0 {
                        "installation verified; use sentinel guard -- claude to activate"
                    } else {
                        "verification failed"
                    }
                ),
                sentinel_core::v2("agent", result),
                code,
            ))
        }
        Command::Guard {
            ref program,
            ref scope,
        } => {
            let code = project.guard(program, scope.clone())?;
            Ok((
                "Guarded provider exited".into(),
                sentinel_core::v2("guard", json!({"exit_code":code})),
                code,
            ))
        }
        Command::Approvals { ref command } => {
            let result = match command {
                ApprovalCommand::List => project.approvals()?,
                ApprovalCommand::Grant { id, binding } => project.approve(id, binding)?,
            };
            let text = serde_json::to_string_pretty(&result).map_err(|_| {
                sentinel_core::Error::Security(1, "Approval output serialization failed")
            })?;
            Ok((
                format!("Exact-action approvals (content redacted):\n{text}"),
                sentinel_core::v2("approvals", result),
                0,
            ))
        }
        Command::Redteam => {
            let result = project.redteam(&std::env::current_exe()?)?;
            let code = if result["passed"] == true { 0 } else { 5 };
            Ok((
                format!(
                    "Synthetic redteam fixtures: {}",
                    if code == 0 { "passed" } else { "failed" }
                ),
                sentinel_core::v2("redteam", result),
                code,
            ))
        }
        Command::Audit {
            command: Some(ref command),
            ..
        } => {
            let result = match command {
                AuditSubcommand::Verify { checkpoint } => {
                    project.audit_verify(checkpoint.as_deref())?
                }
                AuditSubcommand::Checkpoint { output } => project
                    .audit_checkpoint(&sentinel_core::checkpoint_path(&project.root, output))?,
            };
            Ok((
                format!(
                    "Audit integrity: {}",
                    serde_json::to_string(&result).map_err(|_| sentinel_core::Error::Security(
                        1,
                        "Audit output serialization failed"
                    ))?
                ),
                sentinel_core::v2("audit.integrity", result),
                0,
            ))
        }
        Command::Audit {
            command: None,
            limit,
            event,
        } => {
            let history = project.audit_history(limit as usize, event)?;
            let mut message = format!(
                "Audit history: {} events, {} malformed records",
                history.events.len(),
                history.malformed_records
            );
            for event in &history.events {
                message.push_str(&format!(
                    "\n{} {:?} {:?} {:?} (exit {})",
                    event.timestamp,
                    event.event_type,
                    event.command,
                    event.outcome,
                    event.exit_code
                ));
            }
            if !history.complete {
                message
                    .push_str("\nWarning: malformed records were omitted; history is incomplete");
            }
            let code = if history.complete { 0 } else { 1 };
            Ok((message, json!(history), code))
        }
        Command::Init { level, force } => {
            project.initialize(level.into(), force)?;
            Ok((
                "Project policy initialized".into(),
                json!({"config": project.config, "level": Level::from(level)}),
                0,
            ))
        }
        Command::Scan {
            offline,
            fail_on,
            ref sbom,
            scan_type,
            include_ignored,
            reachability,
            exploit_aware,
            ref entrypoint,
            ref python_import,
        } => {
            let report = project.scan(ProjectScanOptions {
                offline,
                sbom: sbom.clone(),
                include_ignored,
                selection: scan_type.map(|kind| match kind {
                    ScanType::Dependencies => ScanSelection::Dependencies,
                    ScanType::Secrets => ScanSelection::Secrets,
                }),
            })?;
            let mut code = report.exit_code(fail_on);
            let analysis = if reachability || exploit_aware {
                Some(project.analysis(
                    &report,
                    sentinel_core::AnalysisOptions {
                        reachability,
                        exploit_aware,
                        offline,
                        entrypoints: entrypoint.clone(),
                        python_imports: sentinel_core::parse_imports(python_import)?,
                    },
                )?)
            } else {
                None
            };
            if let Some(a) = &analysis {
                code = sentinel_core::enriched_exit(code, a);
            }
            if cli.format == Format::Sarif {
                return Ok((
                    "SARIF scan results".into(),
                    sentinel_core::sarif(&report, analysis.as_ref()),
                    code,
                ));
            }
            let mut message = format!(
                "Scan {}: {} packages checked, {} files checked, {} findings",
                if report.complete && analysis.as_ref().is_none_or(|a| a.complete) {
                    "complete"
                } else {
                    "incomplete"
                },
                report.packages_checked,
                report.files_checked,
                report.findings.len()
            );
            for finding in &report.findings {
                if let Some(package) = &finding.package {
                    message.push_str(&format!(
                        "\n{:?}: {} {} {} — {} ({})",
                        finding.severity,
                        package.ecosystem,
                        package.name,
                        package.version,
                        finding
                            .evidence
                            .advisory_id
                            .as_deref()
                            .unwrap_or("unclassified advisory"),
                        finding.files.join(", ")
                    ));
                } else if let Some(location) = &finding.location {
                    message.push_str(&format!(
                        "\n{:?}: {} {}:{}:{} [REDACTED]",
                        finding.severity,
                        finding.rule_id,
                        location.file,
                        location.line,
                        location.column
                    ));
                }
            }
            for diagnostic in &report.diagnostics {
                message.push_str(&format!(
                    "\n{}: {}",
                    diagnostic
                        .package
                        .as_ref()
                        .map(|p| format!("{} {} {}", p.ecosystem, p.name, p.version))
                        .unwrap_or_else(|| diagnostic
                            .file
                            .clone()
                            .unwrap_or_else(|| "scan".into())),
                    diagnostic.message
                ));
            }
            for cache in &report.cache {
                message.push_str(&format!(
                    "\nCached {} {}: {} seconds old{}",
                    cache.package.name,
                    cache.package.version,
                    cache.age_seconds,
                    if cache.stale { " (stale)" } else { "" }
                ));
            }
            if let Some(a) = analysis {
                message.push_str(&format!(
                    "\nOptional analysis: {}",
                    if a.complete {
                        "complete within prototype scope"
                    } else {
                        "incomplete or unknown; inspect evidence"
                    }
                ));
                for finding in &a.findings {
                    let package = report
                        .findings
                        .iter()
                        .find(|f| f.id == finding.finding_id)
                        .and_then(|f| f.package.as_ref())
                        .map(|p| format!("{} {} {}", p.ecosystem, p.name, p.version))
                        .unwrap_or_else(|| "redacted secret finding".into());
                    message.push_str(&format!("\nAnalysis {package}: {}; EPSS {}; KEV {}; risk {}/10; intelligence {}\n  {}",finding.reachability,finding.epss.map(|p|format!("{:.2}%",p*100.0)).unwrap_or_else(||"unknown".into()),finding.kev.map(|v|if v{"listed"}else{"not listed in the available catalog"}).unwrap_or("unknown"),finding.risk_score,finding.intelligence_status,finding.reachability_reason));
                }
                for diagnostic in &a.diagnostics {
                    message.push_str(&format!("\nAnalysis: {diagnostic}"));
                }
                Ok((
                    message,
                    sentinel_core::v2("scan.enriched", json!({"scan":report,"analysis":a})),
                    code,
                ))
            } else {
                Ok((message, json!(report), code))
            }
        }
        Command::Policy {
            command:
                PolicyCommand::Test {
                    ref fixtures,
                    ref changed_files,
                },
        } => {
            let result = project.policy_test(fixtures.as_deref(), changed_files.as_deref())?;
            let code = if result["passed"] == true { 0 } else { 5 };
            Ok((
                format!(
                    "Policy fixtures: {}",
                    if code == 0 { "passed" } else { "failed" }
                ),
                sentinel_core::v2("policy.test", result),
                code,
            ))
        }
        Command::Policy {
            command: PolicyCommand::Check,
        } => {
            let policy = project.check()?;
            Ok((
                "Policy is valid".into(),
                json!({"config": project.config, "level": policy.project.level, "rules": policy.policy.rules.len()}),
                0,
            ))
        }
    }
}
fn emit(value: &Value) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{value}")
}
fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                let _ = error.print();
                return ExitCode::SUCCESS;
            }
            // Clap may reject arguments before a full Cli exists; still honor JSON mode.
            let args: Vec<_> = std::env::args_os().skip(1).collect();
            let mut json_mode = false;
            for (index, arg) in args.iter().enumerate() {
                if arg == "--" {
                    break;
                }
                if arg == "--format=json" {
                    json_mode = true;
                } else if arg == "--format=text" {
                    json_mode = false;
                } else if arg == "--format" {
                    if let Some(value) = args.get(index + 1) {
                        json_mode = value == "json";
                    }
                }
            }
            if json_mode {
                let _ = emit(
                    &json!({"schema_version":1,"status":"error","error":{"code":2,"message":error.to_string()}}),
                );
            }
            let _ = error.print();
            return ExitCode::from(2);
        }
    };
    if matches!(
        cli.command,
        Command::Agent {
            command: AgentCommand::Hook
        }
    ) {
        return hook(&cli);
    }
    match execute(&cli) {
        Ok((message, data, code)) => {
            let result = if cli.format == Format::Sarif {
                emit(&data)
            } else if cli.format == Format::Json {
                emit(&json!({"schema_version":1,"status":"ok","message":message,"data":data}))
            } else if !cli.quiet {
                writeln!(io::stdout().lock(), "{message}")
            } else if matches!(
                cli.command,
                Command::Scan { .. } | Command::Audit { .. } | Command::Doctor
            ) {
                match message.split_once('\n') {
                    Some((_, essential)) => writeln!(io::stdout().lock(), "{essential}"),
                    None => Ok(()),
                }
            } else {
                Ok(())
            };
            if result.is_err() {
                return ExitCode::from(1);
            }
            ExitCode::from(code)
        }
        Err(error) => {
            let code = error.exit_code();
            if cli.format == Format::Sarif {
                let _ = emit(
                    &json!({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Sentinel"}},"results":[],"invocations":[{"executionSuccessful":false,"toolExecutionNotifications":[{"level":"error","message":{"text":error.to_string()}}]}]}]}),
                );
            } else if cli.format == Format::Json {
                let _ = emit(
                    &json!({"schema_version":1,"status":"error","error":{"code":code,"message":error.to_string()}}),
                );
            }
            eprintln!("error: {error}");
            ExitCode::from(code as u8)
        }
    }
}

fn hook(cli: &Cli) -> ExitCode {
    use std::io::Read;
    let evaluate = (|| -> Result<sentinel_core::agent::GateResult, sentinel_core::Error> {
        let mut bytes = Vec::new();
        io::stdin().take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(sentinel_core::Error::Arguments("Hook input exceeds bound"));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| sentinel_core::Error::Arguments("Malformed hook input"))?;
        let nonce = std::env::var("SENTINEL_GUARD_NONCE")
            .map_err(|_| sentinel_core::Error::Security(5, "No guarded session"))?;
        let project = Project::resolve(&cli.project, &cli.config)?;
        project.hook(&value, &nonce)
    })();
    let (decision,reason)=match evaluate{Ok(r) if matches!(r.decision,sentinel_policy::Decision::Allow|sentinel_policy::Decision::LogOnly)=>("allow",r.code),Ok(r)=>("deny",r.code),Err(_)=>("deny","SENTINEL_FAIL_CLOSED: policy, session, audit, installation, or input verification failed")};
    let verdict = json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":decision,"permissionDecisionReason":reason}});
    if emit(&verdict).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}
