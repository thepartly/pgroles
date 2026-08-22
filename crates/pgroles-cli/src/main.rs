//! pgroles CLI — declarative PostgreSQL role policy manager.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kube::api::{ApiResource, DynamicObject, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::{Api, Client};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use tracing::{info, warn};

use pgroles_cli::{
    PlanSummary, apply_role_retirements, candidate, compute_plan, format_bundle_plan_json,
    format_bundle_validation_result, format_managed_scope_summary, format_plan_json,
    format_plan_sql_with_context, format_rendered_bundle, format_role_graph_summary,
    format_validation_result, inject_password_changes, planned_role_drops, read_manifest_file,
    resolve_passwords, validate_bundle_file, validate_manifest,
};
use pgroles_core::diff::{
    ReconciliationMode, additive_ignores_absence_assertions, filter_changes,
    filter_external_role_changes,
};
use pgroles_core::ownership::validate_changes_against_managed_surface;
use pgroles_core::visual::{self, VisualManagedScope, VisualSource};
use pgroles_inspect::{InspectConfig, inspect_drop_role_safety};

// ---------------------------------------------------------------------------
// CLI argument definitions
// ---------------------------------------------------------------------------

/// pgroles — declarative PostgreSQL role & privilege manager.
///
/// Define roles, grants, default privileges, and memberships in a YAML manifest
/// and converge your database to match.
#[derive(Parser)]
#[command(name = "pgroles", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a manifest or bundle file. No database connection required.
    Validate {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,
    },

    /// Show the SQL changes needed to converge the database to the manifest.
    /// Alias: plan.
    #[command(alias = "plan")]
    Diff {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Output format: "sql" for raw SQL, "summary" for a brief summary, "json" for machine-readable JSON.
        #[arg(long, default_value = "sql")]
        format: OutputFormat,

        /// Reconciliation mode: how aggressively to converge the database.
        ///
        /// - authoritative: full convergence — anything not in the manifest is revoked/dropped (default).
        /// - additive: only grant, never revoke — safe for incremental adoption.
        /// - adopt: manage declared roles fully, but never drop undeclared roles.
        #[arg(long, default_value = "authoritative")]
        mode: CliReconciliationMode,

        /// Exit with code 2 when drift is detected (useful for CI gates).
        #[arg(long, default_value_t = true, overrides_with = "no_exit_code")]
        exit_code: bool,

        /// Disable non-zero exit when drift is detected.
        #[arg(long, action = clap::ArgAction::SetTrue, overrides_with = "exit_code")]
        no_exit_code: bool,
    },

    /// Apply the changes to bring the database in sync with the manifest.
    Apply {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Print the SQL that would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,

        /// Reconciliation mode: how aggressively to converge the database.
        ///
        /// - authoritative: full convergence — anything not in the manifest is revoked/dropped (default).
        /// - additive: only grant, never revoke — safe for incremental adoption.
        /// - adopt: manage declared roles fully, but never drop undeclared roles.
        #[arg(long, default_value = "authoritative")]
        mode: CliReconciliationMode,
    },

    /// Inspect the current database state for roles and privileges.
    Inspect {
        /// Path to policy manifest YAML. When provided, scopes output to roles
        /// and schemas declared in the manifest. When omitted, shows all
        /// non-system database roles and privileges.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file. When provided, scopes output to
        /// the composed bundle ownership boundaries.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,
    },

    /// Generate a manifest YAML from the current database state (brownfield adoption).
    ///
    /// Introspects all non-system roles, their grants, default privileges, and
    /// memberships, then emits a flat manifest that reproduces the current state.
    Generate {
        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Refactor the generated manifest into reusable profiles where roles
        /// share an identical schema-relative privilege shape across multiple
        /// schemas. The transformation is deterministic and round-trips: the
        /// produced manifest expands to the exact same role state as the flat
        /// version.
        #[arg(long)]
        suggest_profiles: bool,

        /// Minimum number of distinct schemas a candidate cluster must span
        /// before it becomes a profile. Only meaningful with
        /// `--suggest-profiles`. Default: 2.
        #[arg(long, default_value_t = 2, requires = "suggest_profiles")]
        suggest_min_schemas: usize,
    },

    /// Request an immediate operator reconcile for a Kubernetes PostgresPolicy.
    Reconcile {
        /// Resource to reconcile, either NAME or postgrespolicy/NAME.
        resource: String,

        /// Kubernetes namespace containing the PostgresPolicy.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,

        /// Wait until status.lastHandledReconcileAt reflects this request.
        #[arg(long)]
        wait: bool,

        /// Maximum time to wait, e.g. "30s", "2m", or "1m30s".
        #[arg(long, default_value = "2m", requires = "wait")]
        timeout: String,
    },

    /// Work with PostgresPolicyCandidates: propose content, review what the
    /// operator planned for it, and read the SQL approving it would run.
    ///
    /// Deciding a plan is deliberately not here: a decision is a status write
    /// gated by admission so `decidedBy` records an authenticated identity, and
    /// a CLI verb would blur who authenticated it. Approve and reject with
    /// `kubectl` — see the plan-approval docs.
    Candidate {
        #[command(subcommand)]
        command: CandidateCommands,
    },

    /// Visualize the role graph structure.
    ///
    /// Renders roles, memberships, grants, and default privileges as a graph
    /// in various output formats.
    Graph {
        #[command(subcommand)]
        source: GraphSource,
    },

    /// Compose a policy bundle into a single flat manifest YAML.
    ///
    /// Validates and composes the bundle (rejecting scope/ownership conflicts),
    /// then emits the resulting manifest. The output round-trips through
    /// `pgroles validate -f` / `diff -f` / `apply -f`, and is suitable for
    /// committing as a `PostgresPolicy` source in a GitOps repo.
    RenderBundle {
        /// Path to the policy bundle YAML file.
        #[arg(long)]
        bundle: PathBuf,

        /// Write output to this file instead of stdout.
        #[arg(short, long, conflicts_with = "check")]
        output: Option<PathBuf>,

        /// Suppress the provenance header comment block at the top of the output.
        #[arg(long)]
        no_header: bool,

        /// Compare the rendered output against an existing file and exit
        /// with code 2 if they differ (useful as a CI gate that catches
        /// stale checked-in renders).
        #[arg(long, conflicts_with = "output", value_name = "PATH")]
        check: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CandidateCommands {
    /// File a candidate proposing the content of a local manifest.
    ///
    /// The content is validated through the same path as `pgroles validate`
    /// before anything is sent, so a candidate the API server would reject on
    /// bounds fails locally first. The object is created with `generateName`,
    /// so concurrent filings never collide.
    Create {
        /// Name of the PostgresPolicy this candidate proposes content for.
        #[arg(long)]
        policy: String,

        /// Path to the policy manifest YAML holding the proposed content.
        #[arg(short, long)]
        file: PathBuf,

        /// Name of an earlier candidate this one supersedes.
        #[arg(long)]
        replaces: Option<String>,

        /// Kubernetes namespace.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },

    /// List the candidates filed against a policy.
    List {
        /// Name of the PostgresPolicy.
        #[arg(long)]
        policy: String,

        /// Kubernetes namespace.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },

    /// Show one candidate in detail: its plan, the plan's decision and decider,
    /// staleness, and any promotion outcome.
    Status {
        /// Name of the PostgresPolicyCandidate.
        name: String,

        /// Kubernetes namespace.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },

    /// Show the reviewed plan's SQL — what approving this candidate would mean.
    Diff {
        /// Name of the PostgresPolicyCandidate.
        name: String,

        /// Kubernetes namespace.
        #[arg(short = 'n', long, default_value = "default")]
        namespace: String,
    },
}

#[derive(Subcommand)]
enum GraphSource {
    /// Build the graph from a manifest file (desired state).
    Desired {
        /// Path to the policy manifest YAML file.
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file.
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// Output format.
        #[arg(long, default_value = "tree")]
        format: GraphFormat,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Build the graph from a live database (current state).
    Current {
        /// Path to the policy manifest YAML file (required when --scope=managed unless --bundle is used).
        #[arg(short, long, conflicts_with = "bundle")]
        file: Option<PathBuf>,

        /// Path to the policy bundle YAML file (required when --scope=managed unless --file is used).
        #[arg(long, conflicts_with = "file")]
        bundle: Option<PathBuf>,

        /// PostgreSQL connection string (or set DATABASE_URL).
        #[arg(long, env = "DATABASE_URL")]
        database_url: String,

        /// Which roles to include: "managed" (requires -f) or "all".
        #[arg(long, default_value = "managed")]
        scope: GraphScope,

        /// Output format.
        #[arg(long, default_value = "tree")]
        format: GraphFormat,

        /// Write output to this file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum GraphFormat {
    Tree,
    Json,
    Dot,
    Mermaid,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum GraphScope {
    Managed,
    All,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Sql,
    Summary,
    Json,
}

/// CLI wrapper for `ReconciliationMode` — clap derives the `ValueEnum` from this.
#[derive(Clone, Debug, clap::ValueEnum)]
enum CliReconciliationMode {
    Authoritative,
    Additive,
    Adopt,
}

impl From<CliReconciliationMode> for ReconciliationMode {
    fn from(cli: CliReconciliationMode) -> Self {
        match cli {
            CliReconciliationMode::Authoritative => ReconciliationMode::Authoritative,
            CliReconciliationMode::Additive => ReconciliationMode::Additive,
            CliReconciliationMode::Adopt => ReconciliationMode::Adopt,
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> ExitCode {
    // Initialise tracing (respects RUST_LOG env var, defaults to info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match run(cli).await {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Exit code 2 indicates drift was detected (used by `diff`/`plan`).
const EXIT_DRIFT: u8 = 2;
const REQUESTED_RECONCILE_ANNOTATION: &str = "reconcile.pgroles.io/requestedAt";
const LAST_HANDLED_RECONCILE_AT_STATUS_FIELD: &str = "lastHandledReconcileAt";

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Validate { file, bundle } => {
            cmd_validate(file.as_deref(), bundle.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Diff {
            file,
            bundle,
            database_url,
            format,
            mode,
            exit_code,
            no_exit_code,
        } => {
            cmd_diff(
                file.as_deref(),
                bundle.as_deref(),
                &database_url,
                &format,
                mode.into(),
                exit_code && !no_exit_code,
            )
            .await
        }
        Commands::Apply {
            file,
            bundle,
            database_url,
            dry_run,
            mode,
        } => {
            cmd_apply(
                file.as_deref(),
                bundle.as_deref(),
                &database_url,
                dry_run,
                mode.into(),
            )
            .await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Inspect {
            file,
            bundle,
            database_url,
        } => {
            cmd_inspect(file.as_deref(), bundle.as_deref(), &database_url).await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Generate {
            database_url,
            output,
            suggest_profiles,
            suggest_min_schemas,
        } => {
            cmd_generate(
                &database_url,
                output.as_deref(),
                suggest_profiles,
                suggest_min_schemas,
            )
            .await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Reconcile {
            resource,
            namespace,
            wait,
            timeout,
        } => {
            cmd_reconcile(&resource, &namespace, wait, &timeout).await?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::RenderBundle {
            bundle,
            output,
            no_header,
            check,
        } => cmd_render_bundle(&bundle, output.as_deref(), !no_header, check.as_deref()),
        Commands::Candidate { command } => {
            match command {
                CandidateCommands::Create {
                    policy,
                    file,
                    replaces,
                    namespace,
                } => candidate::cmd_create(&policy, &file, replaces.as_deref(), &namespace).await?,
                CandidateCommands::List { policy, namespace } => {
                    candidate::cmd_list(&policy, &namespace).await?
                }
                CandidateCommands::Status { name, namespace } => {
                    candidate::cmd_status(&name, &namespace).await?
                }
                CandidateCommands::Diff { name, namespace } => {
                    candidate::cmd_diff(&name, &namespace).await?
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Graph { source } => match source {
            GraphSource::Desired {
                file,
                bundle,
                format,
                output,
            } => {
                cmd_graph_desired(
                    file.as_deref(),
                    bundle.as_deref(),
                    &format,
                    output.as_deref(),
                )?;
                Ok(ExitCode::SUCCESS)
            }
            GraphSource::Current {
                file,
                bundle,
                database_url,
                scope,
                format,
                output,
            } => {
                cmd_graph_current(
                    file.as_deref(),
                    bundle.as_deref(),
                    &database_url,
                    &scope,
                    &format,
                    output.as_deref(),
                )
                .await?;
                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Subcommand implementations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileTargetKind {
    PostgresPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileTarget {
    kind: ReconcileTargetKind,
    name: String,
}

fn parse_reconcile_target(resource: &str) -> Result<ReconcileTarget> {
    let trimmed = resource.trim();
    if trimmed.is_empty() {
        anyhow::bail!("resource must not be empty");
    }

    let (kind, name) = match trimmed.split_once('/') {
        Some((kind, name)) => (parse_reconcile_kind(kind)?, name),
        None => (ReconcileTargetKind::PostgresPolicy, trimmed),
    };

    if name.is_empty() {
        anyhow::bail!("resource name must not be empty");
    }

    Ok(ReconcileTarget {
        kind,
        name: name.to_string(),
    })
}

fn parse_reconcile_kind(kind: &str) -> Result<ReconcileTargetKind> {
    match kind.to_ascii_lowercase().as_str() {
        "postgrespolicy" | "postgrespolicies" | "pgr" | "policy" | "policies" => {
            Ok(ReconcileTargetKind::PostgresPolicy)
        }
        other => {
            anyhow::bail!("unsupported reconcile resource kind {other:?}; use postgrespolicy/NAME")
        }
    }
}

fn parse_cli_duration(duration: &str) -> Result<Duration> {
    let duration = duration.trim();
    if duration.is_empty() {
        anyhow::bail!("duration must not be empty");
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for ch in duration.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
            continue;
        }

        if current_num.is_empty() {
            anyhow::bail!("invalid duration {duration:?}: missing number before {ch:?}");
        }

        let num: u64 = current_num
            .parse()
            .with_context(|| format!("invalid duration {duration:?}"))?;
        current_num.clear();

        match ch {
            'h' => total_secs = total_secs.saturating_add(num.saturating_mul(3600)),
            'm' => total_secs = total_secs.saturating_add(num.saturating_mul(60)),
            's' => total_secs = total_secs.saturating_add(num),
            _ => anyhow::bail!("invalid duration {duration:?}: unknown unit {ch:?}"),
        }
    }

    if !current_num.is_empty() {
        let num: u64 = current_num
            .parse()
            .with_context(|| format!("invalid duration {duration:?}"))?;
        total_secs = total_secs.saturating_add(num);
    }

    if total_secs == 0 {
        anyhow::bail!("duration must be greater than zero");
    }

    Ok(Duration::from_secs(total_secs))
}

fn postgres_policy_api(client: Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("pgroles.io", "v1alpha1", "PostgresPolicy");
    let resource = ApiResource::from_gvk_with_plural(&gvk, "postgrespolicies");
    Api::namespaced_with(client, namespace, &resource)
}

fn now_rfc3339_timestamp() -> String {
    jiff::Timestamp::now().to_string()
}

fn handled_reconcile_timestamp(policy: &DynamicObject) -> Option<&str> {
    policy
        .data
        .get("status")?
        .get(LAST_HANDLED_RECONCILE_AT_STATUS_FIELD)?
        .as_str()
}

fn handled_reconcile_at_least(handled: &str, requested: &str) -> Result<bool> {
    let handled: jiff::Timestamp = handled.parse().with_context(|| {
        format!("invalid status.{LAST_HANDLED_RECONCILE_AT_STATUS_FIELD} timestamp {handled:?}")
    })?;
    let requested: jiff::Timestamp = requested
        .parse()
        .with_context(|| format!("invalid requested reconcile timestamp {requested:?}"))?;
    Ok(handled >= requested)
}

async fn cmd_reconcile(resource: &str, namespace: &str, wait: bool, timeout: &str) -> Result<()> {
    let target = parse_reconcile_target(resource)?;
    let client = Client::try_default()
        .await
        .context("failed to create Kubernetes client")?;
    let policies = match target.kind {
        ReconcileTargetKind::PostgresPolicy => postgres_policy_api(client, namespace),
    };
    let requested_at = now_rfc3339_timestamp();
    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                REQUESTED_RECONCILE_ANNOTATION: requested_at,
            }
        }
    });

    policies
        .patch(&target.name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| {
            format!(
                "failed to annotate postgrespolicy/{} in namespace {}",
                target.name, namespace
            )
        })?;

    println!(
        "Requested reconcile for postgrespolicy/{} in namespace {} at {}.",
        target.name, namespace, requested_at
    );

    if wait {
        wait_for_reconcile_handled(&policies, &target.name, &requested_at, timeout).await?;
    }

    Ok(())
}

async fn wait_for_reconcile_handled(
    policies: &Api<DynamicObject>,
    name: &str,
    requested_at: &str,
    timeout: &str,
) -> Result<()> {
    let timeout = parse_cli_duration(timeout)?;
    let started = Instant::now();

    loop {
        let policy = policies
            .get(name)
            .await
            .with_context(|| format!("failed to read postgrespolicy/{name} while waiting"))?;
        if let Some(handled_at) = handled_reconcile_timestamp(&policy)
            && handled_reconcile_at_least(handled_at, requested_at)?
        {
            println!(
                "Reconcile request handled at {} for postgrespolicy/{}.",
                handled_at, name
            );
            return Ok(());
        }

        if started.elapsed() >= timeout {
            anyhow::bail!(
                "timed out waiting for postgrespolicy/{} status.{} to reach {}",
                name,
                LAST_HANDLED_RECONCILE_AT_STATUS_FIELD,
                requested_at
            );
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn cmd_validate(file: Option<&Path>, bundle: Option<&Path>) -> Result<()> {
    if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        warn_undeclared_default_owner(
            validated.composed.manifest.default_owner.as_deref(),
            &validated.composed.expanded.roles,
        );
        print!("{}", format_bundle_validation_result(&validated));
        return Ok(());
    }

    let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
    let yaml = read_manifest_file(file_path)?;
    let validated = validate_manifest(&yaml)?;
    warn_undeclared_default_owner(
        validated.manifest.default_owner.as_deref(),
        &validated.expanded.roles,
    );
    print!("{}", format_validation_result(&validated));
    Ok(())
}

fn cmd_render_bundle(
    bundle_path: &Path,
    output: Option<&Path>,
    include_header: bool,
    check: Option<&Path>,
) -> Result<ExitCode> {
    let validated = validate_bundle_file(bundle_path)?;
    // The source label must be stable across machines so committed renders
    // diff cleanly; use only the bundle file's basename, not its full path.
    let source_label = bundle_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| bundle_path.display().to_string());
    let rendered = format_rendered_bundle(&validated, &source_label, include_header)?;

    if let Some(check_path) = check {
        let existing = std::fs::read_to_string(check_path).with_context(|| {
            format!(
                "failed to read existing rendered file for --check: {}",
                check_path.display()
            )
        })?;
        if existing == rendered {
            info!(path = %check_path.display(), "rendered bundle matches existing file");
            return Ok(ExitCode::SUCCESS);
        }
        eprintln!(
            "rendered bundle differs from {}; regenerate with `pgroles render-bundle --bundle {} --output {}`",
            check_path.display(),
            bundle_path.display(),
            check_path.display(),
        );
        return Ok(ExitCode::from(EXIT_DRIFT));
    }

    match output {
        Some(path) => {
            std::fs::write(path, &rendered).with_context(|| {
                format!("failed to write rendered bundle to {}", path.display())
            })?;
            info!(path = %path.display(), "rendered bundle written");
        }
        None => print!("{rendered}"),
    }
    Ok(ExitCode::SUCCESS)
}

async fn cmd_diff(
    file: Option<&Path>,
    bundle: Option<&Path>,
    database_url: &str,
    format: &OutputFormat,
    mode: ReconciliationMode,
    use_exit_code: bool,
) -> Result<ExitCode> {
    if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        let pool = connect_db(database_url).await?;
        let inspect_config = inspect_config_for_bundle(&validated);
        let current = inspect_current_for_plan_with_config(&pool, &inspect_config).await?;
        info!(%mode, "reconciliation mode");
        warn_additive_absence_assertions(&validated.composed.desired, mode);
        let changes = filter_external_role_changes(
            filter_changes(
                apply_role_retirements(
                    compute_plan(&current, &validated.composed.desired),
                    &validated.composed.manifest.retirements,
                ),
                mode,
            ),
            &validated.composed.expanded.roles,
        );
        warn_adopt_schema_owner_transfers(mode, &changes);
        warn_undeclared_default_owner(
            validated.composed.manifest.default_owner.as_deref(),
            &validated.composed.expanded.roles,
        );
        let resolved_passwords = resolve_passwords(&validated.composed.expanded)
            .context("failed to resolve role passwords")?;
        let changes = inject_password_changes(changes, &resolved_passwords);
        validate_changes_against_managed_surface(
            &changes,
            &validated.composed.managed_change_surface,
        )?;
        preflight_authority(&pool, &changes, &current, false).await?;
        let drop_safety =
            inspect_drop_safety(&pool, &changes, &validated.composed.manifest.retirements).await?;
        let summary = PlanSummary::from_changes(&changes);

        match format {
            OutputFormat::Sql => {
                let sql_ctx = detect_sql_context_with_config(&pool, &inspect_config).await?;
                if summary.is_empty() {
                    println!("-- No changes needed. Database is in sync with manifest.");
                } else {
                    print!("{}", format_plan_sql_with_context(&changes, &sql_ctx));
                    eprintln!("\n{summary}");
                    if !drop_safety.is_empty() {
                        eprintln!("\n{drop_safety}");
                    }
                }
            }
            OutputFormat::Summary => {
                print!("{summary}");
                if !drop_safety.is_empty() {
                    eprintln!("\n{drop_safety}");
                }
            }
            OutputFormat::Json => {
                println!(
                    "{}",
                    format_bundle_plan_json(&changes, &validated.composed)?
                );
            }
        }

        return if use_exit_code && summary.has_structural_changes() {
            Ok(ExitCode::from(EXIT_DRIFT))
        } else {
            Ok(ExitCode::SUCCESS)
        };
    }

    let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
    let yaml = read_manifest_file(file_path)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let current = inspect_current_for_plan(&pool, &validated).await?;

    info!(%mode, "reconciliation mode");
    warn_additive_absence_assertions(&validated.desired, mode);
    let changes = filter_external_role_changes(
        filter_changes(
            apply_role_retirements(
                compute_plan(&current, &validated.desired),
                &validated.manifest.retirements,
            ),
            mode,
        ),
        &validated.expanded.roles,
    );
    warn_adopt_schema_owner_transfers(mode, &changes);
    warn_undeclared_default_owner(
        validated.manifest.default_owner.as_deref(),
        &validated.expanded.roles,
    );
    let resolved_passwords =
        resolve_passwords(&validated.expanded).context("failed to resolve role passwords")?;
    let changes = inject_password_changes(changes, &resolved_passwords);
    preflight_authority(&pool, &changes, &current, false).await?;
    let drop_safety = inspect_drop_safety(&pool, &changes, &validated.manifest.retirements).await?;
    let summary = PlanSummary::from_changes(&changes);

    match format {
        OutputFormat::Sql => {
            let sql_ctx = detect_sql_context(&pool, &validated.expanded).await?;
            if summary.is_empty() {
                println!("-- No changes needed. Database is in sync with manifest.");
            } else {
                print!("{}", format_plan_sql_with_context(&changes, &sql_ctx));
                eprintln!("\n{summary}");
                if !drop_safety.is_empty() {
                    eprintln!("\n{drop_safety}");
                }
            }
        }
        OutputFormat::Summary => {
            print!("{summary}");
            if !drop_safety.is_empty() {
                eprintln!("\n{drop_safety}");
            }
        }
        OutputFormat::Json => {
            println!("{}", format_plan_json(&changes)?);
        }
    }

    // Use structural changes for exit code — password-only changes don't
    // constitute drift because passwords can't be read back for comparison.
    if use_exit_code && summary.has_structural_changes() {
        Ok(ExitCode::from(EXIT_DRIFT))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

async fn cmd_apply(
    file: Option<&Path>,
    bundle: Option<&Path>,
    database_url: &str,
    dry_run: bool,
    mode: ReconciliationMode,
) -> Result<()> {
    if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        let pool = connect_db(database_url).await?;
        let inspect_config = inspect_config_for_bundle(&validated);
        let sql_ctx = detect_sql_context_with_config(&pool, &inspect_config).await?;

        // Detect cloud provider privilege level and warn about unsupported operations.
        let privilege_level = pgroles_inspect::detect_privilege_level(&pool)
            .await
            .context("failed to detect privilege level")?;
        info!(level = %privilege_level, "detected privilege level");

        let current = inspect_current_for_plan_with_config(&pool, &inspect_config).await?;

        info!(%mode, "reconciliation mode");
        warn_additive_absence_assertions(&validated.composed.desired, mode);
        let changes = filter_external_role_changes(
            filter_changes(
                apply_role_retirements(
                    compute_plan(&current, &validated.composed.desired),
                    &validated.composed.manifest.retirements,
                ),
                mode,
            ),
            &validated.composed.expanded.roles,
        );
        warn_adopt_schema_owner_transfers(mode, &changes);
        warn_undeclared_default_owner(
            validated.composed.manifest.default_owner.as_deref(),
            &validated.composed.expanded.roles,
        );
        let resolved_passwords = resolve_passwords(&validated.composed.expanded)
            .context("failed to resolve role passwords")?;
        let changes = inject_password_changes(changes, &resolved_passwords);
        validate_changes_against_managed_surface(
            &changes,
            &validated.composed.managed_change_surface,
        )?;
        // Validate changes against privilege level.
        let priv_warnings = pgroles_inspect::cloud::validate_changes_for_privilege_level(
            &changes,
            &privilege_level,
        );
        if !priv_warnings.is_empty() {
            for warning in &priv_warnings {
                eprintln!("Warning: {warning}");
            }
        }

        let drop_safety =
            inspect_drop_safety(&pool, &changes, &validated.composed.manifest.retirements).await?;
        let summary = PlanSummary::from_changes(&changes);

        if summary.is_empty() {
            println!("No changes needed. Database is in sync with manifest.");
            return Ok(());
        }

        let sql_output = format_plan_sql_with_context(&changes, &sql_ctx);

        if dry_run {
            println!("-- DRY RUN: the following SQL would be executed:\n");
            print!("{sql_output}");
            eprintln!("\n{}", summary.format_plan());
            preflight_authority(&pool, &changes, &current, false).await?;
            if !drop_safety.is_empty() {
                eprintln!("\n{drop_safety}");
            }
            return Ok(());
        }

        preflight_authority(&pool, &changes, &current, true).await?;

        if drop_safety.has_blockers() {
            anyhow::bail!("{}", drop_safety.blockers);
        }

        if !drop_safety.warnings.is_empty() {
            eprintln!("\n{warnings}", warnings = drop_safety.warnings);
        }

        // Execute the entire plan in one transaction to avoid partial convergence.
        info!(changes = summary.total(), "applying changes");
        execute_changes(&pool, &changes, &sql_ctx).await?;

        println!(
            "Applied {total} change(s) successfully.",
            total = summary.total()
        );
        print!("{}", summary.format_applied());

        return Ok(());
    }

    let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
    let yaml = read_manifest_file(file_path)?;
    let validated = validate_manifest(&yaml)?;

    let pool = connect_db(database_url).await?;
    let sql_ctx = detect_sql_context(&pool, &validated.expanded).await?;

    // Detect cloud provider privilege level and warn about unsupported operations.
    let privilege_level = pgroles_inspect::detect_privilege_level(&pool)
        .await
        .context("failed to detect privilege level")?;
    info!(level = %privilege_level, "detected privilege level");

    let current = inspect_current_for_plan(&pool, &validated).await?;

    info!(%mode, "reconciliation mode");
    warn_additive_absence_assertions(&validated.desired, mode);
    let changes = filter_external_role_changes(
        filter_changes(
            apply_role_retirements(
                compute_plan(&current, &validated.desired),
                &validated.manifest.retirements,
            ),
            mode,
        ),
        &validated.expanded.roles,
    );
    warn_adopt_schema_owner_transfers(mode, &changes);
    warn_undeclared_default_owner(
        validated.manifest.default_owner.as_deref(),
        &validated.expanded.roles,
    );
    let resolved_passwords =
        resolve_passwords(&validated.expanded).context("failed to resolve role passwords")?;
    let changes = inject_password_changes(changes, &resolved_passwords);
    // Validate changes against privilege level.
    let priv_warnings =
        pgroles_inspect::cloud::validate_changes_for_privilege_level(&changes, &privilege_level);
    if !priv_warnings.is_empty() {
        for warning in &priv_warnings {
            eprintln!("Warning: {warning}");
        }
    }

    let drop_safety = inspect_drop_safety(&pool, &changes, &validated.manifest.retirements).await?;
    let summary = PlanSummary::from_changes(&changes);

    if summary.is_empty() {
        println!("No changes needed. Database is in sync with manifest.");
        return Ok(());
    }

    let sql_output = format_plan_sql_with_context(&changes, &sql_ctx);

    if dry_run {
        println!("-- DRY RUN: the following SQL would be executed:\n");
        print!("{sql_output}");
        eprintln!("\n{}", summary.format_plan());
        preflight_authority(&pool, &changes, &current, false).await?;
        if !drop_safety.is_empty() {
            eprintln!("\n{drop_safety}");
        }
        return Ok(());
    }

    preflight_authority(&pool, &changes, &current, true).await?;

    if drop_safety.has_blockers() {
        anyhow::bail!("{}", drop_safety.blockers);
    }

    if !drop_safety.warnings.is_empty() {
        eprintln!("\n{warnings}", warnings = drop_safety.warnings);
    }

    // Execute the entire plan in one transaction to avoid partial convergence.
    info!(changes = summary.total(), "applying changes");
    execute_changes(&pool, &changes, &sql_ctx).await?;

    println!(
        "Applied {total} change(s) successfully.",
        total = summary.total()
    );
    print!("{}", summary.format_applied());

    Ok(())
}

async fn cmd_inspect(file: Option<&Path>, bundle: Option<&Path>, database_url: &str) -> Result<()> {
    // Validate manifest or bundle before connecting so YAML errors fail fast.
    let validated_manifest = match (file, bundle) {
        (Some(path), None) => {
            let yaml = read_manifest_file(path)?;
            Some(validate_manifest(&yaml)?)
        }
        (None, Some(_)) | (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let validated_bundle = match (file, bundle) {
        (None, Some(path)) => Some(validate_bundle_file(path)?),
        (Some(_), None) | (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };

    let pool = connect_db(database_url).await?;

    let current = if let Some(ref validated) = validated_manifest {
        inspect_current(&pool, validated).await?
    } else if let Some(ref validated) = validated_bundle {
        let inspect_config = inspect_config_for_bundle(validated);
        inspect_current_with_config(&pool, &inspect_config).await?
    } else {
        info!("no manifest provided, inspecting all non-system roles");
        pgroles_inspect::inspect_all(
            &pool,
            &pgroles_inspect::InspectAllConfig {
                exclude_system_roles: true,
            },
        )
        .await
        .context("failed to introspect database")?
    };

    if let Some(ref validated) = validated_bundle {
        print!(
            "{}",
            format_managed_scope_summary(&validated.composed.managed_scope)
        );
    };

    print!("{}", format_role_graph_summary(&current));

    // Query and display PUBLIC grants (informational only).
    let public_grants = pgroles_inspect::fetch_public_grants(&pool)
        .await
        .context("failed to query PUBLIC grants")?;
    let public_output = pgroles_inspect::format_public_grants(&public_grants);
    if !public_output.is_empty() {
        print!("{public_output}");
    }

    Ok(())
}

async fn cmd_generate(
    database_url: &str,
    output: Option<&Path>,
    suggest_profiles: bool,
    suggest_min_schemas: usize,
) -> Result<()> {
    let pool = connect_db(database_url).await?;

    // Introspect all non-system roles by using an unscoped inspect config.
    info!("introspecting all non-system roles for manifest generation");
    let graph = pgroles_inspect::inspect_all(
        &pool,
        &pgroles_inspect::InspectAllConfig {
            exclude_system_roles: true,
        },
    )
    .await
    .context("failed to introspect database for generation")?;

    let mut manifest = pgroles_core::export::role_graph_to_manifest(&graph);

    if suggest_profiles {
        // Fetch the *complete* per-schema object inventory from the live DB.
        // The suggester needs this to safely collapse per-name grants into
        // wildcards: a grant-derived inventory would treat ungranted objects
        // as nonexistent and could broaden privileges when the suggested
        // manifest is applied.
        let schemas: Vec<String> = manifest.schemas.iter().map(|s| s.name.clone()).collect();
        let schema_refs: Vec<&str> = schemas.iter().map(String::as_str).collect();
        let raw_inventory = pgroles_inspect::fetch_object_inventory(&pool, &schema_refs)
            .await
            .context("failed to fetch object inventory for profile suggestion")?;
        // Translate `(ObjectType, schema) → Vec<name>` into the suggester's
        // `(schema, ObjectType) → BTreeSet<name>` shape.
        let mut full_inventory: pgroles_core::suggest::Inventory =
            std::collections::BTreeMap::new();
        for ((object_type, schema), names) in raw_inventory {
            full_inventory
                .entry((schema, object_type))
                .or_default()
                .extend(names);
        }

        let opts = pgroles_core::suggest::SuggestOptions {
            min_schemas: suggest_min_schemas,
            full_inventory: Some(full_inventory),
        };
        let report = pgroles_core::suggest::suggest_profiles(&manifest, &opts);
        log_suggest_report(&report);
        manifest = report.manifest;
    }

    let yaml = serde_yaml::to_string(&manifest).context("failed to serialize manifest to YAML")?;

    match output {
        Some(path) => {
            std::fs::write(path, &yaml)
                .with_context(|| format!("failed to write output to {}", path.display()))?;
            info!(path = %path.display(), "manifest written");
        }
        None => print!("{yaml}"),
    }

    Ok(())
}

fn log_suggest_report(report: &pgroles_core::suggest::SuggestReport) {
    use pgroles_core::suggest::SkipReason;

    if !report.round_trip_ok {
        warn!("profile suggestion round-trip check failed; emitting flat manifest");
    }
    info!(
        profiles_extracted = report.profiles.len(),
        roles_skipped = report.skipped.len(),
        "profile suggestion complete"
    );
    for p in &report.profiles {
        let schemas: Vec<&str> = p.schema_to_role.keys().map(String::as_str).collect();
        info!(
            profile = %p.profile_name,
            pattern = %p.role_pattern,
            schemas = ?schemas,
            replaced_roles = ?p.schema_to_role.values().collect::<Vec<_>>(),
            "extracted profile"
        );
    }
    for skip in &report.skipped {
        match skip {
            SkipReason::MultiSchema { role, schemas } => {
                info!(role, ?schemas, "skipped: role spans multiple schemas");
            }
            SkipReason::SchemaNotDeclared { role, schema } => {
                info!(role, schema, "skipped: schema not declared in manifest");
            }
            SkipReason::OwnerMismatch { role, schema } => {
                info!(
                    role,
                    schema, "skipped: default privilege owner != schema owner"
                );
            }
            SkipReason::UniqueAttributes { role } => {
                info!(role, "skipped: role has attributes profiles can't express");
            }
            SkipReason::UnrepresentableGrant { role } => {
                info!(role, "skipped: role has grants profiles can't express");
            }
            SkipReason::SoleSchema { role, schema } => {
                info!(role, schema, "skipped: cluster spans only one schema");
            }
            SkipReason::NoUniformPattern { roles } => {
                info!(
                    ?roles,
                    "skipped: no uniform role-name pattern across cluster"
                );
            }
            SkipReason::SchemaPatternConflict {
                schema,
                winning_pattern,
                dropped_roles,
            } => {
                info!(
                    schema,
                    winning_pattern,
                    ?dropped_roles,
                    "skipped: schema pattern conflict"
                );
            }
            SkipReason::RoundTripFailure { reason } => {
                warn!(reason, "skipped: round-trip failure");
            }
            SkipReason::IncompleteFullInventory { reason } => {
                warn!(
                    reason,
                    "full_inventory looked incomplete; wildcard collapse disabled for safety"
                );
            }
        }
    }
}

fn cmd_graph_desired(
    file: Option<&Path>,
    bundle: Option<&Path>,
    format: &GraphFormat,
    output: Option<&Path>,
) -> Result<()> {
    let visual = if let Some(bundle_path) = bundle {
        let validated = validate_bundle_file(bundle_path)?;
        let mut visual =
            visual::build_visual_graph(&validated.composed.desired, VisualSource::Desired);
        if matches!(format, GraphFormat::Json) {
            visual.meta.managed_scope =
                Some(VisualManagedScope::from(&validated.composed.managed_scope));
        }
        visual
    } else {
        let file_path = file.unwrap_or_else(|| Path::new("pgroles.yaml"));
        let yaml = read_manifest_file(file_path)?;
        let validated = validate_manifest(&yaml)?;
        visual::build_visual_graph(&validated.desired, VisualSource::Desired)
    };

    let rendered = render_graph(&visual, format);
    write_output(&rendered, output)
}

async fn cmd_graph_current(
    file: Option<&Path>,
    bundle: Option<&Path>,
    database_url: &str,
    scope: &GraphScope,
    format: &GraphFormat,
    output: Option<&Path>,
) -> Result<()> {
    // Validate file requirement before connecting to the database.
    if matches!(scope, GraphScope::Managed) && file.is_none() && bundle.is_none() {
        anyhow::bail!(
            "--file or --bundle is required when --scope=managed (to determine which roles are managed)"
        );
    }

    let pool = connect_db(database_url).await?;

    let graph = match scope {
        GraphScope::Managed => {
            if let Some(bundle_path) = bundle {
                let validated = validate_bundle_file(bundle_path)?;
                let inspect_config = inspect_config_for_bundle(&validated);
                let graph = inspect_current_with_config(&pool, &inspect_config).await?;
                let mut visual = visual::build_visual_graph(&graph, VisualSource::Current);
                if matches!(format, GraphFormat::Json) {
                    visual.meta.managed_scope =
                        Some(VisualManagedScope::from(&validated.composed.managed_scope));
                }
                let rendered = render_graph(&visual, format);
                return write_output(&rendered, output);
            } else {
                let file = file.expect("validated above");
                let yaml = read_manifest_file(file)?;
                let validated = validate_manifest(&yaml)?;
                inspect_current(&pool, &validated).await?
            }
        }
        GraphScope::All => {
            info!("introspecting all non-system roles");
            pgroles_inspect::inspect_all(
                &pool,
                &pgroles_inspect::InspectAllConfig {
                    exclude_system_roles: true,
                },
            )
            .await
            .context("failed to introspect database")?
        }
    };

    let visual = visual::build_visual_graph(&graph, VisualSource::Current);
    let rendered = render_graph(&visual, format);
    write_output(&rendered, output)
}

fn render_graph(visual: &visual::VisualGraph, format: &GraphFormat) -> String {
    match format {
        GraphFormat::Tree => visual::render_tree(visual),
        GraphFormat::Json => visual::render_json(visual),
        GraphFormat::Dot => visual::render_dot(visual),
        GraphFormat::Mermaid => visual::render_mermaid(visual),
    }
}

fn write_output(content: &str, output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, content)
                .with_context(|| format!("failed to write output to {}", path.display()))?;
            info!(path = %path.display(), "output written");
        }
        None => print!("{content}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn connect_db(database_url: &str) -> Result<PgPool> {
    info!("connecting to database");
    // The CLI is a one-shot tool, so prefer a single pooled connection. This
    // avoids hopping across different backends when a hostname resolves to
    // multiple PostgreSQL servers.
    PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .context("failed to connect to database")
}

#[derive(Debug, Clone)]
struct ExecutionBackendInfo {
    server_addr: String,
    server_port: String,
    backend_pid: i32,
    database_name: String,
    user_name: String,
    in_recovery: bool,
}

impl std::fmt::Display for ExecutionBackendInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "server={} port={} pid={} db={} user={} recovery={}",
            self.server_addr,
            self.server_port,
            self.backend_pid,
            self.database_name,
            self.user_name,
            self.in_recovery
        )
    }
}

async fn fetch_execution_backend_info<'e, E>(
    executor: E,
) -> Result<ExecutionBackendInfo, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        r#"
        SELECT
            COALESCE(inet_server_addr()::text, 'local') AS server_addr,
            COALESCE(inet_server_port()::text, 'local') AS server_port,
            pg_backend_pid() AS backend_pid,
            current_database() AS database_name,
            current_user AS user_name,
            pg_is_in_recovery() AS in_recovery
        "#,
    )
    .fetch_one(executor)
    .await?;

    Ok(ExecutionBackendInfo {
        server_addr: row.get("server_addr"),
        server_port: row.get("server_port"),
        backend_pid: row.get("backend_pid"),
        database_name: row.get("database_name"),
        user_name: row.get("user_name"),
        in_recovery: row.get("in_recovery"),
    })
}

fn render_execution_failure(
    statement: &str,
    backend: Option<&ExecutionBackendInfo>,
    error: &sqlx::Error,
) -> String {
    let backend_suffix = backend
        .map(|backend| format!(" on backend [{backend}]"))
        .unwrap_or_default();

    if let Some(database_error) = error.as_database_error() {
        let code = database_error
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let message = database_error.message();
        format!("failed to execute: {statement}{backend_suffix}: SQLSTATE {code}: {message}")
    } else {
        format!("failed to execute: {statement}{backend_suffix}: {error}")
    }
}

async fn execute_changes(
    pool: &PgPool,
    changes: &[pgroles_core::diff::Change],
    sql_ctx: &pgroles_core::sql::SqlContext,
) -> Result<()> {
    let mut transaction = pool.begin().await.context("failed to start transaction")?;
    let execution_backend = match fetch_execution_backend_info(transaction.as_mut()).await {
        Ok(backend) => {
            info!(backend = %backend, "using execution backend");
            Some(backend)
        }
        Err(error) => {
            tracing::warn!(%error, "failed to query execution backend details");
            None
        }
    };

    for change in changes {
        let is_sensitive = matches!(change, pgroles_core::diff::Change::SetPassword { .. });
        for statement in pgroles_core::sql::render_statements_with_context(change, sql_ctx) {
            let statement_for_error = if is_sensitive {
                "ALTER ROLE ... PASSWORD [REDACTED]".to_string()
            } else {
                statement.clone()
            };
            if is_sensitive {
                info!("executing: ALTER ROLE ... PASSWORD [REDACTED]");
            } else {
                info!(sql = %statement, "executing");
            }
            if let Err(error) = sqlx::query(&statement).execute(transaction.as_mut()).await {
                anyhow::bail!(
                    "{}",
                    render_execution_failure(
                        &statement_for_error,
                        execution_backend.as_ref(),
                        &error
                    )
                );
            }
        }
    }
    transaction
        .commit()
        .await
        .context("failed to commit transaction")?;

    Ok(())
}

async fn detect_sql_context(
    pool: &PgPool,
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> Result<pgroles_core::sql::SqlContext> {
    let inspect_config = InspectConfig::from_expanded(expanded, false);
    detect_sql_context_with_config(pool, &inspect_config).await
}

async fn detect_sql_context_with_config(
    pool: &PgPool,
    inspect_config: &InspectConfig,
) -> Result<pgroles_core::sql::SqlContext> {
    let pg_version = pgroles_inspect::detect_pg_version(pool)
        .await
        .context("failed to detect PostgreSQL version")?;
    let privilege_schemas: Vec<&str> = inspect_config
        .privilege_schemas
        .iter()
        .map(|schema| schema.as_str())
        .collect();
    let relation_inventory = pgroles_inspect::fetch_relation_inventory(pool, &privilege_schemas)
        .await
        .context("failed to inspect relation inventory")?;
    info!(
        pg_major = pg_version.major(),
        "detected PostgreSQL server version"
    );
    Ok(
        pgroles_core::sql::SqlContext::from_version_num(pg_version.version_num)
            .with_relation_inventory(relation_inventory),
    )
}

async fn inspect_current(
    pool: &PgPool,
    validated: &pgroles_cli::ValidatedManifest,
) -> Result<pgroles_core::model::RoleGraph> {
    let config = inspect_config_for_manifest(validated);
    inspect_current_with_config(pool, &config).await
}

fn inspect_config_for_manifest(validated: &pgroles_cli::ValidatedManifest) -> InspectConfig {
    let has_database_grants = validated
        .expanded
        .grants
        .iter()
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);

    InspectConfig::from_expanded(&validated.expanded, has_database_grants).with_additional_roles(
        validated
            .manifest
            .retirements
            .iter()
            .map(|retirement| retirement.role.clone()),
    )
}

async fn inspect_current_for_plan(
    pool: &PgPool,
    validated: &pgroles_cli::ValidatedManifest,
) -> Result<pgroles_core::model::RoleGraph> {
    let config = inspect_config_for_manifest(validated);
    inspect_current_for_plan_with_config(pool, &config).await
}

fn inspect_config_for_bundle(validated: &pgroles_cli::ValidatedBundle) -> InspectConfig {
    InspectConfig::from_managed_scope(
        &validated.composed.managed_scope,
        &validated.composed.expanded,
        validated
            .composed
            .managed_change_surface
            .needs_database_privilege_inspection(),
    )
    .with_additional_roles(
        validated
            .composed
            .manifest
            .retirements
            .iter()
            .map(|retirement| retirement.role.clone()),
    )
}

async fn inspect_current_with_config(
    pool: &PgPool,
    config: &InspectConfig,
) -> Result<pgroles_core::model::RoleGraph> {
    info!(
        managed_roles = config.managed_roles.len(),
        managed_schemas = config.managed_schemas.len(),
        privilege_schemas = config.privilege_schemas.len(),
        "inspecting current database state"
    );

    pgroles_inspect::inspect(pool, config)
        .await
        .context("failed to inspect database state")
}

async fn inspect_current_for_plan_with_config(
    pool: &PgPool,
    config: &InspectConfig,
) -> Result<pgroles_core::model::RoleGraph> {
    info!(
        managed_roles = config.managed_roles.len(),
        managed_schemas = config.managed_schemas.len(),
        privilege_schemas = config.privilege_schemas.len(),
        "inspecting current database state"
    );

    let inspection = pgroles_inspect::inspect_with_diagnostics(pool, config)
        .await
        .context("failed to inspect database state")?;
    // Unsatisfiable wildcard grants mean the desired state cannot be reliably
    // computed, so they block diff/apply from proceeding.
    if let Some(message) = inspection.diagnostics.blocking_message() {
        anyhow::bail!("{message}");
    }
    // Column-level grants are advisory only — pgroles doesn't manage them, but
    // diff/apply should still proceed. Warn instead of failing.
    for diagnostic in &inspection.diagnostics.column_level_grants {
        eprintln!("Warning: {diagnostic}");
    }
    Ok(inspection.graph)
}

/// Report planned default-privilege changes and PUBLIC revokes the executor
/// lacks the authority to perform. Runs on the final change list, so converged
/// state never reports anything.
///
/// `blocking` is true only where SQL actually runs. `diff` and `apply
/// --dry-run` execute nothing, so they warn and still produce their plan —
/// a CI drift check running as a read-only role keeps working. This mirrors
/// how drop safety is handled, which also warns until the moment of execution.
async fn preflight_authority(
    pool: &PgPool,
    changes: &[pgroles_core::diff::Change],
    current: &pgroles_core::model::RoleGraph,
    blocking: bool,
) -> Result<()> {
    let issues = pgroles_inspect::preflight_authority_issues(pool, changes, current)
        .await
        .context("failed to check executor authority")?;
    if issues.is_empty() {
        return Ok(());
    }
    let message = issues
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    if blocking {
        anyhow::bail!("{message}");
    }
    for issue in &issues {
        eprintln!("Warning: {issue}");
    }
    Ok(())
}

fn warn_additive_absence_assertions(
    desired: &pgroles_core::model::RoleGraph,
    mode: ReconciliationMode,
) {
    if additive_ignores_absence_assertions(desired, mode) {
        eprintln!(
            "Warning: additive reconciliation ignores every `ensure: absent` assertion; \
             use adopt or authoritative mode to enforce absence"
        );
    }
}

/// Warn when adopt mode transfers schema ownership.
///
/// Adopt filters role drops, not ownership convergence: a binding whose
/// declared owner differs from the live one is transferred even under adopt.
fn warn_adopt_schema_owner_transfers(
    mode: ReconciliationMode,
    changes: &[pgroles_core::diff::Change],
) {
    if mode != ReconciliationMode::Adopt {
        return;
    }
    for change in changes {
        if let pgroles_core::diff::Change::AlterSchemaOwner { name, owner } = change {
            eprintln!(
                "Warning: adopt mode transfers ownership of schema \"{name}\" to \"{owner}\"; \
                 use additive mode if the current owner must be preserved"
            );
        }
    }
}

/// Warn when `default_owner` names a role the manifest never declares.
///
/// An undeclared default owner is invisible to inspection — its privileges
/// are neither inspected nor converged — while still claiming ownership of
/// every schema binding without an explicit `owner:`. A typo here therefore
/// silently changes what the policy claims.
fn warn_undeclared_default_owner(
    default_owner: Option<&str>,
    expanded_roles: &[pgroles_core::manifest::RoleDefinition],
) {
    let Some(owner) = default_owner else {
        return;
    };
    if !expanded_roles.iter().any(|role| role.name == owner) {
        eprintln!(
            "Warning: default_owner \"{owner}\" is not declared under roles; it will not be \
             inspected or converged, but every schema binding without an explicit owner \
             resolves to it. Declare it (external: true) or set the owner per schema."
        );
    }
}

async fn inspect_drop_safety(
    pool: &PgPool,
    changes: &[pgroles_core::diff::Change],
    retirements: &[pgroles_core::manifest::RoleRetirement],
) -> Result<pgroles_inspect::DropRoleSafetyAssessment> {
    let dropped_roles = planned_role_drops(changes);
    let report = inspect_drop_role_safety(pool, &dropped_roles)
        .await
        .context("failed to inspect role-drop safety")?;
    Ok(report.assess(retirements))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::model::{RoleGraph, RoleState};
    use sqlx::error::{DatabaseError, ErrorKind};

    #[derive(Debug)]
    struct TestDatabaseError {
        message: String,
        code: Option<&'static str>,
    }

    impl std::fmt::Display for TestDatabaseError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::error::Error for TestDatabaseError {}

    impl DatabaseError for TestDatabaseError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.map(std::borrow::Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[test]
    fn parse_reconcile_target_defaults_to_postgres_policy() {
        let target = parse_reconcile_target("accounts").expect("target should parse");

        assert_eq!(target.kind, ReconcileTargetKind::PostgresPolicy);
        assert_eq!(target.name, "accounts");
    }

    #[test]
    fn parse_reconcile_target_accepts_postgres_policy_kind() {
        let target =
            parse_reconcile_target("postgrespolicy/accounts").expect("target should parse");

        assert_eq!(target.kind, ReconcileTargetKind::PostgresPolicy);
        assert_eq!(target.name, "accounts");
    }

    #[test]
    fn parse_reconcile_target_rejects_unsupported_kind() {
        let error =
            parse_reconcile_target("secret/accounts").expect_err("unsupported kind should fail");

        assert!(
            error
                .to_string()
                .contains("unsupported reconcile resource kind")
        );
    }

    #[test]
    fn parse_cli_duration_accepts_compound_duration() {
        assert_eq!(
            parse_cli_duration("1m30s").expect("duration should parse"),
            Duration::from_secs(90)
        );
    }

    #[test]
    fn handled_reconcile_at_least_compares_rfc3339_timestamps() {
        assert!(
            handled_reconcile_at_least("2026-05-15T00:00:01Z", "2026-05-15T00:00:00Z")
                .expect("timestamps should parse")
        );
        assert!(
            !handled_reconcile_at_least("2026-05-14T23:59:59Z", "2026-05-15T00:00:00Z")
                .expect("timestamps should parse")
        );
    }

    fn sample_visual_graph() -> pgroles_core::visual::VisualGraph {
        let mut graph = RoleGraph::default();
        graph.roles.insert(
            "analytics".to_string(),
            RoleState {
                login: true,
                ..RoleState::default()
            },
        );
        visual::build_visual_graph(&graph, VisualSource::Desired)
    }

    #[test]
    fn render_graph_delegates_to_requested_format() {
        let visual = sample_visual_graph();

        assert_eq!(
            render_graph(&visual, &GraphFormat::Tree),
            visual::render_tree(&visual)
        );
        assert_eq!(
            render_graph(&visual, &GraphFormat::Json),
            visual::render_json(&visual)
        );
        assert_eq!(
            render_graph(&visual, &GraphFormat::Dot),
            visual::render_dot(&visual)
        );
        assert_eq!(
            render_graph(&visual, &GraphFormat::Mermaid),
            visual::render_mermaid(&visual)
        );
    }

    #[test]
    fn write_output_writes_file_when_path_provided() {
        let dir = tempfile::tempdir().expect("failed to create tempdir");
        let path = dir.path().join("graph.txt");

        write_output("graph output", Some(&path)).expect("write_output should succeed");

        let written = std::fs::read_to_string(&path).expect("failed to read output file");
        assert_eq!(written, "graph output");
    }

    #[test]
    fn graph_current_managed_requires_file_before_connecting() {
        let runtime = tokio::runtime::Runtime::new().expect("failed to create runtime");
        let error = runtime
            .block_on(cmd_graph_current(
                None,
                None,
                "postgres://unused",
                &GraphScope::Managed,
                &GraphFormat::Tree,
                None,
            ))
            .expect_err("managed graph without --file/--bundle should fail");

        assert!(
            error
                .to_string()
                .contains("--file or --bundle is required when --scope=managed"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn render_execution_failure_includes_backend_and_sqlstate() {
        let backend = ExecutionBackendInfo {
            server_addr: "10.0.0.5".to_string(),
            server_port: "5432".to_string(),
            backend_pid: 4242,
            database_name: "pgroles_test".to_string(),
            user_name: "postgres".to_string(),
            in_recovery: false,
        };
        let error = sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "role \"accounts-editor\" does not exist".to_string(),
            code: Some("42704"),
        }));

        let rendered = render_execution_failure(
            r#"ALTER ROLE "accounts-editor" NOLOGIN INHERIT;"#,
            Some(&backend),
            &error,
        );

        assert!(rendered.contains("SQLSTATE 42704"));
        assert!(rendered.contains("server=10.0.0.5"));
        assert!(rendered.contains("role \"accounts-editor\" does not exist"));
    }

    #[test]
    fn render_execution_failure_without_database_error_falls_back_to_display() {
        let error = sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::TimedOut));
        let rendered = render_execution_failure("SELECT 1;", None, &error);

        assert!(rendered.contains("failed to execute: SELECT 1;"));
        assert!(rendered.contains("timed out"));
    }
}
