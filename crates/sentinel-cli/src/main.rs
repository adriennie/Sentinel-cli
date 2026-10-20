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
    },
    /// Diagnose configuration, storage, cache and supported capabilities offline.
    Doctor,
    /// Read local redacted audit history (no integrity guarantee).
    Audit {
        #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=10000))]
        limit: u32,
        #[arg(long, value_parser = parse_event)]
        event: Option<AuditEventType>,
    },
    /// Inspect project security policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
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
}
fn execute(cli: &Cli) -> Result<(String, Value, u8), sentinel_core::Error> {
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
    };
    let code = result
        .as_ref()
        .map(|(_, _, code)| *code)
        .unwrap_or_else(|error| error.exit_code() as u8);
    let packages = result
        .as_ref()
        .ok()
        .and_then(|(_, data, _)| data.get("packages_checked").and_then(Value::as_u64));
    let findings = result.as_ref().ok().and_then(|(_, data, _)| {
        data.get("findings")
            .and_then(Value::as_array)
            .map(|values| values.len() as u64)
    });
    let logging = project.record_command(command, code, packages, findings);
    match (result, logging) {
        (Ok((message, mut data, code)), Ok(state)) => {
            data["audit_logging"] = json!(state);
            Ok((message, data, code))
        }
        (Ok((message, mut data, code)), Err(error)) => {
            eprintln!("warning: {error}");
            data["audit_logging"] = json!("failed");
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
        Command::Audit { limit, event } => {
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
            let code = report.exit_code(fail_on);
            let mut message = format!(
                "Scan {}: {} packages checked, {} files checked, {} findings",
                report.status,
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
            Ok((message, json!(report), code))
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
    match execute(&cli) {
        Ok((message, data, code)) => {
            let result = if cli.format == Format::Json {
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
            if cli.format == Format::Json {
                let _ = emit(
                    &json!({"schema_version":1,"status":"error","error":{"code":code,"message":error.to_string()}}),
                );
            }
            eprintln!("error: {error}");
            ExitCode::from(code as u8)
        }
    }
}
