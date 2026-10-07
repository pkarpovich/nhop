use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;
use nhop_ipc::{HealthState, UpstreamAddr};
use serde::{Deserialize, Serialize};

use crate::logging::{cause_name, health_name};

/// What produced a verdict turnover.
///
/// The log carries it so a reader can tell an upstream a user's own connection found unusable from
/// one the daemon's patrol judged on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictCause {
    /// A patrol probe the daemon made for itself.
    Probe,
    /// A real dial a connection paid for.
    Dial,
}

/// Why new connections moved from one upstream to another.
///
/// Derived once per switch from the selection before and after it, so a reader of the log can tell
/// traffic leaving an upstream that failed from traffic returning to one that has stayed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchCause {
    /// The upstream that was carrying new connections turned down.
    Down,
    /// A higher-ranked upstream stayed up for the whole return hold and took traffic back.
    Held,
    /// An upstream came up while none was selectable.
    Recovered,
    /// A load published a different list.
    Reload,
}

/// Verdict on the upstream and the instant it settled.
///
/// The instant is a [`SystemTime`] rather than an [`Instant`] because `status` and `doctor` render
/// it as an RFC3339 string.
///
/// [`SystemTime`]: std::time::SystemTime
/// [`Instant`]: std::time::Instant
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// Whether the upstream is usable.
    pub state: HealthState,
    /// When the verdict last turned over.
    pub changed_at: SystemTime,
}

impl Default for Health {
    fn default() -> Self {
        Self {
            state: HealthState::Down,
            changed_at: SystemTime::now(),
        }
    }
}

/// Verdict on the upstream, shared by the state task, the dialer and every connection.
///
/// A daemon starts [`HealthState::Down`], so no `prefer` destination is sent through an upstream
/// that has not answered anything yet. A `require` destination is dialled from that cold verdict,
/// since it has no direct route to be spared for.
#[derive(Debug, Clone)]
pub struct HealthHandle(Arc<Judged>);

/// The address a verdict is about and the verdict itself.
#[derive(Debug)]
struct Judged {
    upstream: UpstreamAddr,
    health: ArcSwap<Health>,
}

impl HealthHandle {
    /// Returns a fresh [`HealthState::Down`] verdict on `upstream`, named on every turnover line.
    ///
    /// With several upstreams a turnover line that does not say which one turned over cannot be
    /// read.
    pub fn judging(upstream: UpstreamAddr) -> Self {
        Self(Arc::new(Judged {
            upstream,
            health: ArcSwap::default(),
        }))
    }

    /// Returns the verdict and the instant it settled.
    pub fn verdict(&self) -> Health {
        let Self(judged) = self;
        let Judged {
            upstream: _,
            health,
        } = &**judged;
        **health.load()
    }

    /// Returns the verdict in force at this instant.
    pub fn state(&self) -> HealthState {
        let Health {
            state,
            changed_at: _,
        } = self.verdict();
        state
    }

    /// Returns when the verdict last turned over.
    pub fn changed_at(&self) -> SystemTime {
        let Health {
            state: _,
            changed_at,
        } = self.verdict();
        changed_at
    }

    /// Records one observation made now, moving `changed_at` and logging a line only on a turnover.
    ///
    /// It is [`HealthHandle::set_at`] stamped with [`SystemTime::now`], the form a real dial uses.
    pub fn set(&self, state: HealthState, cause: VerdictCause) {
        self.set_at(state, cause, SystemTime::now());
    }

    /// Records one observation, stamping a turnover with `at` and logging a line only on a turnover.
    ///
    /// The line carries `upstream` - the written address this handle judges - beside
    /// `verdict_from`, `verdict_to` and `cause`.
    ///
    /// The patrol stamps every write of one round with the instant the round started, so entries
    /// whose sequences close in the same round settle at the same instant and [`select`] breaks
    /// the tie by list order rather than by which probe happened to return first.
    ///
    /// The line is written here because this is the one place a turnover can be seen: the settled
    /// verdict and the observation are only both in hand while the swap is being made.
    ///
    /// [`select`]: crate::upstream::select
    pub fn set_at(&self, state: HealthState, cause: VerdictCause, at: SystemTime) {
        let previous = self.settle(state, at);
        let Self(judged) = self;
        let Judged {
            upstream: UpstreamAddr(upstream),
            health: _,
        } = &**judged;
        let Health {
            state: previous,
            changed_at: _,
        } = *previous;
        match (previous, state) {
            (HealthState::Up, HealthState::Up) | (HealthState::Down, HealthState::Down) => {}
            (HealthState::Up, HealthState::Down) | (HealthState::Down, HealthState::Up) => {
                tracing::info!(
                    upstream = upstream.as_str(),
                    verdict_from = health_name(previous),
                    verdict_to = health_name(state),
                    cause = cause_name(cause),
                );
            }
        }
    }

    /// Establishes a starting verdict, observing nothing and logging nothing.
    ///
    /// A test that needs a daemon to begin [`HealthState::Up`] is arranging the world, not watching
    /// it move; [`HealthHandle::set`] is for the observations under test.
    pub fn seed(&self, state: HealthState) {
        let _previous = self.settle(state, SystemTime::now());
    }

    /// Returns whether both handles judge the same verdict rather than two equal ones.
    ///
    /// A reload keeps an entry's handle only while it keeps the address, so two handles that are
    /// the same judge one address published without a break in between.
    pub fn same(&self, other: &HealthHandle) -> bool {
        let Self(judged) = self;
        let Self(other) = other;
        Arc::ptr_eq(judged, other)
    }

    fn settle(&self, state: HealthState, at: SystemTime) -> Arc<Health> {
        let Self(judged) = self;
        let Judged {
            upstream: _,
            health,
        } = &**judged;
        health.rcu(|settled| {
            let Health {
                state: settled,
                changed_at,
            } = **settled;
            let changed_at = match (settled, state) {
                (HealthState::Up, HealthState::Up) | (HealthState::Down, HealthState::Down) => {
                    changed_at
                }
                (HealthState::Up, HealthState::Down) | (HealthState::Down, HealthState::Up) => at,
            };
            Health { state, changed_at }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use nhop_ipc::Paths;

    use super::*;
    use crate::logging;

    const TICK: Duration = Duration::from_millis(2);
    const JUDGED: &str = "socks5://192.0.2.11:1080";

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct VerdictFields {
        #[serde(default)]
        upstream: Option<UpstreamAddr>,
        verdict_from: HealthState,
        verdict_to: HealthState,
        cause: VerdictCause,
    }

    fn judged() -> HealthHandle {
        HealthHandle::judging(UpstreamAddr(JUDGED.to_owned()))
    }

    fn recorded(observe: impl FnOnce(&HealthHandle)) -> Vec<VerdictFields> {
        recorded_on(judged(), observe)
    }

    fn recorded_on(
        health: HealthHandle,
        observe: impl FnOnce(&HealthHandle),
    ) -> Vec<VerdictFields> {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let subscriber = logging::subscriber(&paths).unwrap();
        tracing::subscriber::with_default(subscriber, || observe(&health));
        let mut records = Vec::new();
        for file in logging::files(&paths).unwrap() {
            let (lines, _offset) = logging::read_from(&file, 0).unwrap();
            for line in lines {
                let line: serde_json::Value = serde_json::from_str(&line).unwrap();
                let fields = line.get("fields").unwrap().clone();
                records.push(serde_json::from_value(fields).unwrap());
            }
        }
        records
    }

    #[test]
    fn a_fresh_verdict_is_down() {
        let health = judged();
        assert_eq!(health.state(), HealthState::Down);
        assert!(health.changed_at() <= SystemTime::now());
    }

    #[test]
    fn one_success_flips_up_and_moves_the_instant() {
        let health = judged();
        let settled = health.changed_at();
        sleep(TICK);

        health.seed(HealthState::Up);

        assert_eq!(health.state(), HealthState::Up);
        assert!(health.changed_at() > settled);
    }

    #[test]
    fn one_failure_flips_down_and_moves_the_instant() {
        let health = judged();
        health.seed(HealthState::Up);
        let settled = health.changed_at();
        sleep(TICK);

        health.seed(HealthState::Down);

        assert_eq!(health.state(), HealthState::Down);
        assert!(health.changed_at() > settled);
    }

    #[test]
    fn an_observation_that_confirms_the_verdict_leaves_the_instant_alone() {
        let health = judged();
        health.seed(HealthState::Up);
        let settled = health.verdict();

        health.seed(HealthState::Up);
        health.seed(HealthState::Up);

        assert_eq!(health.verdict(), settled);
    }

    #[test]
    fn every_holder_of_the_handle_reads_the_same_verdict() {
        let health = judged();
        let elsewhere = health.clone();

        elsewhere.seed(HealthState::Up);

        assert_eq!(health.verdict(), elsewhere.verdict());
    }

    #[test]
    fn a_turnover_set_at_an_instant_settles_at_that_instant() {
        let health = judged();
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);

        health.set_at(HealthState::Up, VerdictCause::Probe, at);
        health.set_at(
            HealthState::Up,
            VerdictCause::Probe,
            at + Duration::from_secs(5),
        );

        assert_eq!(
            health.verdict(),
            Health {
                state: HealthState::Up,
                changed_at: at,
            }
        );
    }

    #[test]
    fn a_clone_is_the_same_handle_and_a_fresh_one_is_not() {
        let health = judged();

        assert!(health.same(&health.clone()));
        assert!(!health.same(&judged()));
    }

    #[test]
    fn a_repeated_verdict_emits_no_line() {
        let records = recorded(|health| {
            health.set(HealthState::Down, VerdictCause::Probe);
            health.set(HealthState::Down, VerdictCause::Dial);
        });

        assert!(records.is_empty(), "{records:?}");
    }

    #[test]
    fn a_turnover_emits_one_line_with_its_cause() {
        let records = recorded(|health| {
            health.set(HealthState::Up, VerdictCause::Dial);
            health.set(HealthState::Up, VerdictCause::Probe);
        });

        assert_eq!(
            records,
            vec![VerdictFields {
                upstream: Some(UpstreamAddr(JUDGED.to_owned())),
                verdict_from: HealthState::Down,
                verdict_to: HealthState::Up,
                cause: VerdictCause::Dial,
            }]
        );
    }

    #[test]
    fn a_turnover_names_the_upstream_it_judges() {
        let judged = UpstreamAddr("socks5://192.0.2.11:1080".to_owned());

        let records = recorded_on(HealthHandle::judging(judged.clone()), |health| {
            health.set(HealthState::Up, VerdictCause::Probe);
        });

        assert_eq!(
            records,
            vec![VerdictFields {
                upstream: Some(judged),
                verdict_from: HealthState::Down,
                verdict_to: HealthState::Up,
                cause: VerdictCause::Probe,
            }]
        );
    }
}
