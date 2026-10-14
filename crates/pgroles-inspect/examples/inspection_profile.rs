//! Reproducible phase measurements against a disposable, pre-populated database.
//! DATABASE_URL=... cargo run --release -p pgroles-inspect --example inspection_profile -- policy.yaml
use pgroles_core::{
    manifest::{expand_manifest, parse_manifest},
    model::RoleGraph,
};
use pgroles_inspect::{InspectConfig, RawInspection};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Run on a worker, like the operator; tokio::main's root future otherwise
    // runs on the calling thread and hides worker starvation in inline mode.
    tokio::spawn(profile()).await?
}

async fn profile() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filename = std::env::args().nth(1).ok_or("expected manifest path")?;
    let manifest = parse_manifest(&std::fs::read_to_string(filename)?)?;
    let expanded = expand_manifest(&manifest)?;
    let desired = RoleGraph::from_expanded(&expanded, None)?;
    let config = InspectConfig::from_expanded(&expanded, false);
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let lag = Arc::new(AtomicU64::new(0));
    let measured_lag = Arc::clone(&lag);
    let sampler = tokio::spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_millis(10));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let scheduled = timer.tick().await;
            measured_lag.fetch_max(scheduled.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    for iteration in 0..5 {
        let start = Instant::now();
        let raw = Arc::new(RawInspection::read(&pool, &config).await?);
        let read = start.elapsed();
        let start = Instant::now();
        let inspection = if std::env::var_os("PROFILE_INLINE").is_some() {
            raw.derive(&pool, &config).await?
        } else {
            raw.derive_bounded(&pool, &config).await?
        };
        let derive = start.elapsed();
        let start = Instant::now();
        let changes = pgroles_core::diff::diff(&inspection.graph, &desired);
        let diff = start.elapsed();
        let start = Instant::now();
        // Option changes need executor attribution before they render; this
        // profile measures the pure pipeline, so it counts only what renders
        // and reports how many changes it left out.
        let rendered: Vec<_> = changes
            .iter()
            .map(pgroles_core::sql::render_statements)
            .collect();
        let unrendered = rendered.iter().filter(|r| r.is_err()).count();
        let statements: Vec<_> = rendered.into_iter().flatten().flatten().collect();
        println!(
            "iteration={iteration} read={read:?} derive={derive:?} diff={diff:?} render={:?} acl_rows={} grant_keys={} grantor_keys={} changes={} statements={} unrendered={unrendered} phases={:?}",
            start.elapsed(),
            inspection.stats.acl_rows,
            inspection.stats.grants,
            inspection.stats.grantor_keys,
            changes.len(),
            statements.len(),
            inspection.stats.phase_durations
        );
    }
    println!("runtime_timer_max_lag_us={}", lag.load(Ordering::Relaxed));
    sampler.abort();
    Ok(())
}
