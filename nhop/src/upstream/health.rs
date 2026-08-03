use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;
use nhop_ipc::HealthState;

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
/// A daemon starts [`HealthState::Down`], so nothing is dialled through an upstream that has not
/// answered anything yet.
#[derive(Debug, Clone)]
pub struct HealthHandle(Arc<ArcSwap<Health>>);

impl Default for HealthHandle {
    fn default() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(Health::default())))
    }
}

impl HealthHandle {
    /// Returns the verdict and the instant it settled.
    pub fn verdict(&self) -> Health {
        let Self(health) = self;
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

    /// Records one observation, moving `changed_at` only when the verdict turns over.
    pub fn set(&self, state: HealthState) {
        let Self(health) = self;
        let _previous = health.rcu(|settled| {
            let Health {
                state: settled,
                changed_at,
            } = **settled;
            let changed_at = match (settled, state) {
                (HealthState::Up, HealthState::Up) | (HealthState::Down, HealthState::Down) => {
                    changed_at
                }
                (HealthState::Up, HealthState::Down) | (HealthState::Down, HealthState::Up) => {
                    SystemTime::now()
                }
            };
            Health { state, changed_at }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    const TICK: Duration = Duration::from_millis(2);

    #[test]
    fn a_fresh_verdict_is_down() {
        let health = HealthHandle::default();
        assert_eq!(health.state(), HealthState::Down);
        assert!(health.changed_at() <= SystemTime::now());
    }

    #[test]
    fn one_success_flips_up_and_moves_the_instant() {
        let health = HealthHandle::default();
        let settled = health.changed_at();
        sleep(TICK);

        health.set(HealthState::Up);

        assert_eq!(health.state(), HealthState::Up);
        assert!(health.changed_at() > settled);
    }

    #[test]
    fn one_failure_flips_down_and_moves_the_instant() {
        let health = HealthHandle::default();
        health.set(HealthState::Up);
        let settled = health.changed_at();
        sleep(TICK);

        health.set(HealthState::Down);

        assert_eq!(health.state(), HealthState::Down);
        assert!(health.changed_at() > settled);
    }

    #[test]
    fn an_observation_that_confirms_the_verdict_leaves_the_instant_alone() {
        let health = HealthHandle::default();
        health.set(HealthState::Up);
        let settled = health.verdict();

        health.set(HealthState::Up);
        health.set(HealthState::Up);

        assert_eq!(health.verdict(), settled);
    }

    #[test]
    fn every_holder_of_the_handle_reads_the_same_verdict() {
        let health = HealthHandle::default();
        let elsewhere = health.clone();

        elsewhere.set(HealthState::Up);

        assert_eq!(health.verdict(), elsewhere.verdict());
    }
}
