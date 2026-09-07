//! Controller readiness tracks synchronization and supervision, not object success.
use std::sync::{Arc, Mutex};

use futures::{Stream, StreamExt};
use kube::runtime::watcher;

use crate::observability::OperatorObservability;

/// The three supervised reconcilers; labels never contain resource names.
#[derive(Clone, Copy)]
pub enum ControllerKind {
    Policy,
    AccessPolicy,
    AccessRequest,
}
impl ControllerKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::AccessPolicy => "access_policy",
            Self::AccessRequest => "access_request",
        }
    }
}

/// Fixed watch identities prevent object names from creating metric cardinality.
#[derive(Clone, Copy, Debug)]
pub enum WatchKind {
    Policies,
    Secrets,
    Plans,
    Candidates,
    AccessPolicies,
    AccessPolicyTargets,
    AccessRequests,
    AccessRequestPolicies,
}

impl WatchKind {
    pub const ALL: [Self; 8] = [
        Self::Policies,
        Self::Secrets,
        Self::Plans,
        Self::Candidates,
        Self::AccessPolicies,
        Self::AccessPolicyTargets,
        Self::AccessRequests,
        Self::AccessRequestPolicies,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Policies => "policies",
            Self::Secrets => "secrets",
            Self::Plans => "plans",
            Self::Candidates => "candidates",
            Self::AccessPolicies => "access_policies",
            Self::AccessPolicyTargets => "access_policy_targets",
            Self::AccessRequests => "access_requests",
            Self::AccessRequestPolicies => "access_request_policies",
        }
    }
}

#[derive(Default)]
struct State {
    synced: u8,
    stopped: bool,
}

#[derive(Clone)]
pub struct ControllerHealth {
    state: Arc<Mutex<State>>,
    observability: OperatorObservability,
}

impl ControllerHealth {
    pub fn new(observability: OperatorObservability) -> Self {
        observability.mark_not_ready();
        for kind in WatchKind::ALL {
            observability.record_watch_sync(kind, false);
        }
        Self {
            state: Arc::default(),
            observability,
        }
    }

    /// Place after reflect/index updates, but before flattening InitDone away.
    pub fn watch<K, S>(
        &self,
        kind: WatchKind,
        input: S,
    ) -> impl Stream<Item = Result<watcher::Event<K>, watcher::Error>> + use<K, S>
    where
        S: Stream<Item = Result<watcher::Event<K>, watcher::Error>>,
    {
        let health = self.clone();
        input.inspect(move |event| health.observe(kind, event))
    }

    fn observe<K>(&self, kind: WatchKind, event: &Result<watcher::Event<K>, watcher::Error>) {
        let mut state = self.state.lock().expect("controller health mutex poisoned");
        let bit = 1 << kind as u8;
        match event {
            Ok(watcher::Event::Init) => {
                state.synced &= !bit;
                self.observability.record_watch_sync(kind, false);
            }
            Ok(watcher::Event::InitDone) => {
                state.synced |= bit;
                self.observability.record_watch_sync(kind, true);
            }
            _ => {}
        }
        self.observability.record_watch_event(kind, event.is_ok());
        // Watch reconnects can be quiet: kube does not surface connection-open
        // events or bookmarks. Errors are diagnostic, not a readiness timeout.
        if state.synced == u8::MAX && !state.stopped {
            self.observability.mark_ready();
        } else {
            self.observability.mark_not_ready();
        }
    }

    /// Sticky: late watch events during drain cannot restore readiness.
    pub fn stop(&self) {
        let mut state = self.state.lock().expect("controller health mutex poisoned");
        state.stopped = true;
        self.observability.mark_not_ready();
    }
}

/// Stop accepting work on a signal or any required controller exit, then drain.
/// Returns true for unexpected termination so main can return a failing status.
pub async fn supervise(
    health: ControllerHealth,
    mut controllers: impl Stream<Item = ()> + Unpin,
    signal: impl std::future::Future<Output = ()>,
    shutdown: futures::channel::oneshot::Sender<()>,
) -> bool {
    let unexpected_exit = tokio::select! {
        biased;
        _ = signal => false,
        _ = controllers.next() => true,
    };
    health.stop();
    let _ = shutdown.send(());
    while controllers.next().await.is_some() {}
    unexpected_exit
}

/// Register both signal handlers before polling controllers.
pub fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()> + Send + Sync> {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    Ok(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use k8s_openapi::api::core::v1::Secret;
    use kube::runtime::{WatchStreamExt, reflector};

    #[tokio::test]
    async fn empty_reflectors_and_trigger_watches_sync_without_objects() {
        let observability = OperatorObservability::disabled();
        let health = ControllerHealth::new(observability.clone());
        for (index, kind) in WatchKind::ALL.into_iter().enumerate() {
            assert!(!observability.is_ready());
            let (reader, writer) = reflector::store::<Secret>();
            let input = stream::iter(vec![Ok(watcher::Event::Init), Ok(watcher::Event::InitDone)])
                .reflect(writer);
            // Exercise the same adapter and flattening as main: even empty
            // initial lists must update health and publish the empty store.
            assert_eq!(health.watch(kind, input).applied_objects().count().await, 0);
            reader.wait_until_ready().await.unwrap();
            assert!(reader.state().is_empty());
            assert_eq!(observability.is_ready(), index == 7);
        }
        // Idle controllers receive no further events and remain ready.
        tokio::task::yield_now().await;
        assert!(observability.is_ready());
        // Individual policy failure is a progress observation, not health.
        observability.record_controller_progress(ControllerKind::Policy, false);
        assert!(observability.is_ready());
    }

    #[tokio::test]
    async fn reconnect_relist_and_shutdown_have_distinct_semantics() {
        let observability = OperatorObservability::disabled();
        let health = ControllerHealth::new(observability.clone());
        let error = || watcher::Error::NoResourceVersion;
        health.observe::<Secret>(WatchKind::Policies, &Err(error()));
        assert!(!observability.is_ready());
        for kind in WatchKind::ALL {
            health.observe::<Secret>(kind, &Ok(watcher::Event::InitDone));
        }
        health.observe::<Secret>(WatchKind::Policies, &Err(error()));
        assert!(
            observability.is_ready(),
            "quiet reconnects cannot prove failure"
        );
        health.observe::<Secret>(WatchKind::Policies, &Ok(watcher::Event::Init));
        assert!(!observability.is_ready());
        health.observe::<Secret>(WatchKind::Policies, &Ok(watcher::Event::InitDone));
        assert!(observability.is_ready());
        health.stop();
        health.observe::<Secret>(WatchKind::Policies, &Ok(watcher::Event::InitDone));
        assert!(!observability.is_ready(), "shutdown is sticky during drain");
    }
    #[tokio::test]
    async fn supervisor_clears_readiness_before_draining_on_exit_or_signal() {
        use futures::FutureExt;
        for unexpected in [false, true] {
            let observability = OperatorObservability::disabled();
            let health = ControllerHealth::new(observability.clone());
            for kind in WatchKind::ALL {
                health.observe::<Secret>(kind, &Ok(watcher::Event::InitDone));
            }
            let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();
            let (drain_tx, drain_rx) = futures::channel::oneshot::channel();
            let controllers = futures::stream::FuturesUnordered::new();
            controllers.push(
                async move {
                    shutdown_rx.await.unwrap();
                    drain_rx.await.unwrap();
                }
                .boxed(),
            );
            if unexpected {
                controllers.push(futures::future::ready(()).boxed());
            }
            let signal = async move {
                if unexpected {
                    futures::future::pending::<()>().await;
                }
            };
            let task = tokio::spawn(supervise(health, controllers, signal, shutdown_tx));
            tokio::task::yield_now().await;
            assert!(!observability.is_ready());
            assert!(!task.is_finished(), "must wait for in-flight work cleanup");
            drain_tx.send(()).unwrap();
            assert_eq!(task.await.unwrap(), unexpected);
        }
    }
    #[tokio::test]
    async fn real_controller_poll_graph_initializes_empty_primary_and_dependency_watches() {
        use futures::FutureExt;
        use kube::runtime::{Controller, controller::Action, reflector::ObjectRef};
        fn empty_watch() -> impl Stream<Item = Result<watcher::Event<Secret>, watcher::Error>> {
            stream::iter([Ok(watcher::Event::Init), Ok(watcher::Event::InitDone)])
                .chain(stream::pending())
        }
        let observability = OperatorObservability::disabled();
        let health = ControllerHealth::new(observability.clone());
        let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel::<()>();
        let shutdown = shutdown_rx.map(|_| ()).shared();
        let controllers = futures::stream::FuturesUnordered::new();
        for watches in [
            &WatchKind::ALL[..4],
            &WatchKind::ALL[4..6],
            &WatchKind::ALL[6..],
        ] {
            let (reader, writer) = reflector::store::<Secret>();
            let primary = health
                .watch(watches[0], empty_watch().reflect(writer))
                .applied_objects();
            let mut controller = Controller::for_stream(primary, reader);
            for &watch in &watches[1..] {
                let triggers = health
                    .watch(watch, empty_watch())
                    .touched_objects()
                    .filter_map(|result| async move {
                        result.ok().map(|object| ObjectRef::from_obj(&object))
                    });
                controller = controller.reconcile_on(triggers);
            }
            let running = controller
                .graceful_shutdown_on(shutdown.clone())
                .run(
                    |_, _: Arc<()>| async { Ok::<_, std::io::Error>(Action::await_change()) },
                    |_, _, _| Action::await_change(),
                    Arc::new(()),
                )
                .for_each(|_| async {});
            controllers.push(running.boxed());
        }
        let task = tokio::spawn(async move { controllers.collect::<Vec<_>>().await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !observability.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("real controllers must poll dependent empty watches");
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
