//! Which published upstream new connections go through, and the log of every move between them.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use nhop_ipc::{HealthState, UpstreamAddr};

use crate::logging::switch_cause_name;
use crate::proxy::Upstream;
use crate::upstream::{Health, SwitchCause, UpstreamEntries};

/// How long a higher-ranked upstream has to stay up before it takes new connections back.
///
/// Sixty seconds is twice the period of the worst flapping seen on a real upstream, which turned
/// its verdict over about every 30 seconds, so a primary in that state never wins traffic back
/// while one that is genuinely back takes over within a minute plus one probe cycle. It applies
/// only to winning traffic back: an upstream that turns down loses it at once.
pub const RETURN_HOLD: Duration = Duration::from_secs(60);

/// Whether an upstream has been up for the whole return hold.
#[derive(Debug, Clone, Copy)]
enum Held {
    Yes,
    No,
}

/// Returns the index of the entry new connections go through, absent while none is up.
///
/// The choice is made in three steps:
///
/// 1. the first entry that is [`HealthState::Up`] and has been for at least `hold`;
/// 2. otherwise the `Up` entry that has been up longest, ties going to list order;
/// 3. otherwise nothing.
///
/// The first step is the hysteresis: a primary that has just come back does not take traffic from
/// a fallback that is serving until it has stayed up for `hold`. The second keeps cold start and
/// the only-one-alive case immediate without letting an unheld higher-ranked entry preempt an
/// unheld lower-ranked one that came up first, which is what keeps a flapping primary from
/// bouncing traffic back and forth. An entry whose verdict settled after `now` - the wall clock
/// moved back - has not held, and still orders by its instant in the second step.
///
/// It is a pure function of the verdicts and the clock, so it keeps no state to drift from them:
/// while the clock does not move back, a selected `Up` entry is never displaced by a lower-ranked
/// one until it turns down.
pub fn select(entries: &[Health], now: SystemTime, hold: Duration) -> Option<usize> {
    let mut longest: Option<(usize, SystemTime)> = None;
    for (index, verdict) in entries.iter().enumerate() {
        let Health { state, changed_at } = *verdict;
        match state {
            HealthState::Down => continue,
            HealthState::Up => {}
        }
        match held(changed_at, now, hold) {
            Held::Yes => return Some(index),
            Held::No => {}
        }
        let Some((_earliest, since)) = longest else {
            longest = Some((index, changed_at));
            continue;
        };
        if changed_at < since {
            longest = Some((index, changed_at));
        }
    }
    let (index, _since) = longest?;
    Some(index)
}

fn held(changed_at: SystemTime, now: SystemTime, hold: Duration) -> Held {
    let Ok(up_for) = now.duration_since(changed_at) else {
        return Held::No;
    };
    match up_for >= hold {
        true => Held::Yes,
        false => Held::No,
    }
}

/// The selection last observed and the list it was made from.
#[derive(Debug, Default)]
struct Observed {
    list: Arc<UpstreamEntries>,
    selected: Option<usize>,
}

/// One move of new connections from one upstream to another, either side possibly none.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Switch {
    from: Option<UpstreamAddr>,
    to: Option<UpstreamAddr>,
    cause: SwitchCause,
}

/// Last selection seen by any dial or patrol round, kept only to log each switch once.
///
/// Routing never reads it: every connection recomputes [`select`] from the published list. What it
/// remembers is the selected index and the [`Arc`] of the list it indexes, so "the list changed"
/// is a pointer comparison rather than a content one.
#[derive(Debug, Clone, Default)]
pub struct Selection(Arc<ArcSwap<Observed>>);

impl Selection {
    /// Records the selection `new` made from `list`, logging one line when it moved.
    ///
    /// The line carries `upstream_from`, `upstream_to` - the written addresses, empty for none -
    /// and `switch_cause`. A selection that dials the same socket address as the previous one is no
    /// switch, even when a reload moved that address to another position or spelled it another way. Several callers seeing
    /// the same move log it once, since only the first of them swaps out the selection before it.
    /// A selection made from a list a reload has since replaced, which a dial that read its snapshot
    /// just before the reload still holds, records nothing: it would log a switch back to the old
    /// list and another forward again at the next observation.
    pub fn observe(&self, list: &Arc<UpstreamEntries>, new: Option<usize>) {
        let Some(switch) = self.switched(list, new) else {
            return;
        };
        let Switch { from, to, cause } = switch;
        tracing::info!(
            upstream_from = logged_addr(from.as_ref()),
            upstream_to = logged_addr(to.as_ref()),
            switch_cause = switch_cause_name(cause),
        );
    }

    fn switched(&self, list: &Arc<UpstreamEntries>, new: Option<usize>) -> Option<Switch> {
        let Self(observed) = self;
        let previous = observed.rcu(|current| {
            let Observed {
                list: current_list,
                selected: _,
            } = &**current;
            match list.published_before(current_list) {
                true => Arc::clone(current),
                false => Arc::new(Observed {
                    list: Arc::clone(list),
                    selected: new,
                }),
            }
        });
        let Observed {
            list: previous_list,
            selected: previous,
        } = &*previous;
        if list.published_before(previous_list) {
            return None;
        }
        let from = upstream_at(previous_list, *previous);
        let to = upstream_at(list, new);
        let same = match (from, to) {
            (Some(from), Some(to)) => from.socket() == to.socket(),
            (None, None) => true,
            (Some(_), None) | (None, Some(_)) => false,
        };
        if same {
            return None;
        }
        let cause = match Arc::ptr_eq(previous_list, list) {
            false => SwitchCause::Reload,
            true => cause(list, *previous, new),
        };
        Some(Switch {
            from: from.map(|upstream| upstream.written().clone()),
            to: to.map(|upstream| upstream.written().clone()),
            cause,
        })
    }
}

/// Derives why the selection moved within one list, by the rows of the switch-cause table.
///
/// The previous entry having turned down comes first, then a higher-ranked entry taking over, then
/// one appearing from none. While its verdict holds, a selected `Up` entry is never displaced by a
/// lower-ranked one, so with a monotonic clock those rows cover every move; the shapes they leave
/// out - the previous entry still up and given up for a lower-ranked entry or for none - need it
/// to have turned over unseen between two observations, or the wall clock to have moved back, and
/// read as the previous entry having gone down.
fn cause(list: &UpstreamEntries, previous: Option<usize>, new: Option<usize>) -> SwitchCause {
    let Some(previous) = previous else {
        return SwitchCause::Recovered;
    };
    let state = match list.as_slice().get(previous) {
        Some(entry) => entry.health().state(),
        None => HealthState::Down,
    };
    match state {
        HealthState::Down => return SwitchCause::Down,
        HealthState::Up => {}
    }
    let Some(new) = new else {
        return SwitchCause::Down;
    };
    match new < previous {
        true => SwitchCause::Held,
        false => SwitchCause::Down,
    }
}

fn upstream_at(list: &UpstreamEntries, index: Option<usize>) -> Option<&Upstream> {
    let entry = list.as_slice().get(index?)?;
    Some(entry.upstream())
}

fn logged_addr(addr: Option<&UpstreamAddr>) -> &str {
    match addr {
        Some(UpstreamAddr(text)) => text,
        None => "",
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use nhop_ipc::Paths;
    use serde::Deserialize;

    use super::*;
    use crate::daemon::state::LiveUpstream;
    use crate::logging;
    use crate::proxy::Upstreams;

    const HOLD: Duration = Duration::from_secs(60);
    const P: &str = "192.0.2.10:1080";
    const F: &str = "192.0.2.11:1080";
    const G: &str = "192.0.2.12:1080";

    fn at(millis: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000) + Duration::from_millis(millis)
    }

    fn secs(seconds: u64) -> SystemTime {
        at(seconds * 1000)
    }

    fn up(changed_at: SystemTime) -> Health {
        Health {
            state: HealthState::Up,
            changed_at,
        }
    }

    fn down(changed_at: SystemTime) -> Health {
        Health {
            state: HealthState::Down,
            changed_at,
        }
    }

    fn written_as(addr: &str) -> UpstreamAddr {
        UpstreamAddr(format!("socks5://{addr}"))
    }

    fn listed(addrs: &[&str]) -> Upstreams {
        let Some((first, rest)) = addrs.split_first() else {
            panic!("a staged list names at least one upstream");
        };
        let mut fallbacks = Vec::with_capacity(rest.len());
        for addr in rest {
            fallbacks.push(written_as(addr));
        }
        Upstreams::parse(written_as(first), fallbacks).unwrap()
    }

    fn published(live: &LiveUpstream, addrs: &[&str]) -> Arc<UpstreamEntries> {
        live.publish(&listed(addrs));
        live.snapshot()
    }

    fn seeded(list: &UpstreamEntries, verdicts: &[Health]) {
        for (entry, verdict) in list.as_slice().iter().zip(verdicts) {
            let Health {
                state,
                changed_at: _,
            } = *verdict;
            entry.health().seed(state);
        }
    }

    struct Row {
        name: &'static str,
        verdicts: Vec<Health>,
        now: SystemTime,
        selected: Option<usize>,
    }

    #[test]
    fn selection_follows_the_list_order_and_the_hold() {
        let rows = vec![
            Row {
                name: "one entry up",
                verdicts: vec![up(secs(100))],
                now: secs(101),
                selected: Some(0),
            },
            Row {
                name: "one entry down",
                verdicts: vec![down(secs(0))],
                now: secs(101),
                selected: None,
            },
            Row {
                name: "primary up and held",
                verdicts: vec![up(secs(0)), up(secs(0))],
                now: secs(60),
                selected: Some(0),
            },
            Row {
                name: "primary not held, fallback held",
                verdicts: vec![up(secs(50)), up(secs(0))],
                now: secs(60),
                selected: Some(1),
            },
            Row {
                name: "primary not held, fallback down",
                verdicts: vec![up(secs(50)), down(secs(0))],
                now: secs(60),
                selected: Some(0),
            },
            Row {
                name: "cold start, both up in one round",
                verdicts: vec![up(secs(10)), up(secs(10))],
                now: secs(11),
                selected: Some(0),
            },
            Row {
                name: "neither held, fallback up first",
                verdicts: vec![up(secs(10)), up(secs(5))],
                now: secs(11),
                selected: Some(1),
            },
            Row {
                name: "primary down, fallback up",
                verdicts: vec![down(secs(0)), up(secs(10))],
                now: secs(11),
                selected: Some(1),
            },
            Row {
                name: "everything down",
                verdicts: vec![down(secs(0)), down(secs(0)), down(secs(0))],
                now: secs(100),
                selected: None,
            },
            Row {
                name: "primary settled after now has not held",
                verdicts: vec![up(secs(200)), up(secs(50))],
                now: secs(100),
                selected: Some(1),
            },
            Row {
                name: "trace: F up at 0",
                verdicts: vec![down(secs(0)), up(secs(0))],
                now: secs(0),
                selected: Some(1),
            },
            Row {
                name: "trace: P up at 10",
                verdicts: vec![up(secs(10)), up(secs(0))],
                now: secs(10),
                selected: Some(1),
            },
            Row {
                name: "trace: F held at 60",
                verdicts: vec![up(secs(10)), up(secs(0))],
                now: secs(60),
                selected: Some(1),
            },
            Row {
                name: "trace: P held at 70",
                verdicts: vec![up(secs(10)), up(secs(0))],
                now: secs(70),
                selected: Some(0),
            },
        ];

        for Row {
            name,
            verdicts,
            now,
            selected,
        } in rows
        {
            assert_eq!(select(&verdicts, now, HOLD), selected, "{name}");
        }
    }

    const NOW: u64 = 100_000;
    const NEXT: u64 = 101_000;
    const INSTANTS: [u64; 6] = [0, 40_000, 40_500, 41_000, 60_000, NOW];

    fn turned(verdict: Health) -> Health {
        let Health {
            state,
            changed_at: _,
        } = verdict;
        let state = match state {
            HealthState::Up => HealthState::Down,
            HealthState::Down => HealthState::Up,
        };
        Health {
            state,
            changed_at: at(NEXT),
        }
    }

    fn by_the_table(
        previous: Option<usize>,
        new: Option<usize>,
        after: &[Health],
    ) -> Option<SwitchCause> {
        if let Some(previous) = previous {
            let Health {
                state,
                changed_at: _,
            } = after[previous];
            if state == HealthState::Down {
                return Some(SwitchCause::Down);
            }
        }
        if let (Some(previous), Some(new)) = (previous, new)
            && new < previous
        {
            return Some(SwitchCause::Held);
        }
        if let (None, Some(_new)) = (previous, new) {
            return Some(SwitchCause::Recovered);
        }
        None
    }

    #[test]
    fn every_switch_has_exactly_one_cause() {
        let live = LiveUpstream::default();
        let list = published(&live, &[P, F, G]);
        let mut verdicts = Vec::new();
        for instant in INSTANTS {
            verdicts.push(up(at(instant)));
            verdicts.push(down(at(instant)));
        }

        let mut causes = Vec::new();
        for first in &verdicts {
            for second in &verdicts {
                for third in &verdicts {
                    let before = [*first, *second, *third];
                    for turnovers in 0..8u8 {
                        let mut after = before;
                        for (index, verdict) in after.iter_mut().enumerate() {
                            if turnovers & (1 << index) != 0 {
                                *verdict = turned(*verdict);
                            }
                        }
                        let previous = select(&before, at(NOW), HOLD);
                        let new = select(&after, at(NEXT), HOLD);
                        let selection = Selection::default();
                        seeded(&list, &before);
                        let _primed = selection.switched(&list, previous);
                        seeded(&list, &after);

                        let switch = selection.switched(&list, new);

                        let case = format!("{before:?} -> {after:?}: {previous:?} -> {new:?}");
                        let Some(Switch {
                            from: _,
                            to: _,
                            cause,
                        }) = switch
                        else {
                            assert_eq!(previous, new, "a move logged nothing: {case}");
                            continue;
                        };
                        assert_ne!(previous, new, "an unchanged selection logged: {case}");
                        if !causes.contains(&cause) {
                            causes.push(cause);
                        }
                        let Some(row) = by_the_table(previous, new, &after) else {
                            panic!("no row of the table matches: {case}");
                        };
                        assert_eq!(cause, row, "{case}");
                        if let Some(previous) = previous
                            && after[previous] == before[previous]
                        {
                            let Health {
                                state,
                                changed_at: _,
                            } = after[previous];
                            if state == HealthState::Up {
                                let Some(new) = new else {
                                    panic!("an up entry was given up for none: {case}");
                                };
                                assert!(new < previous, "a lower-ranked entry took over: {case}");
                            }
                        }
                    }
                }
            }
        }
        for cause in [SwitchCause::Down, SwitchCause::Held, SwitchCause::Recovered] {
            assert!(causes.contains(&cause), "no switch derived {cause:?}");
        }

        let reordered = published(&live, &[G, F, P]);
        let states = [HealthState::Up, HealthState::Down];
        for previous in [None, Some(0), Some(1), Some(2)] {
            for new in [None, Some(0), Some(1), Some(2)] {
                for first in states {
                    for third in states {
                        list.as_slice()[0].health().seed(first);
                        list.as_slice()[2].health().seed(third);
                        let selection = Selection::default();
                        let _primed = selection.switched(&list, previous);

                        let switch = selection.switched(&reordered, new);

                        let from = upstream_at(&list, previous).map(Upstream::written).cloned();
                        let to = upstream_at(&reordered, new).map(Upstream::written).cloned();
                        let expected = match from == to {
                            true => None,
                            false => Some(Switch {
                                from,
                                to,
                                cause: SwitchCause::Reload,
                            }),
                        };
                        assert_eq!(switch, expected, "{previous:?} -> {new:?}");
                    }
                }
            }
        }

        let trace = published(&live, &[P, F]);
        let observations = [
            (secs(0), [down(secs(0)), up(secs(0))]),
            (secs(10), [up(secs(10)), up(secs(0))]),
            (secs(60), [up(secs(10)), up(secs(0))]),
            (secs(70), [up(secs(10)), up(secs(0))]),
        ];
        let selection = Selection::default();
        let mut moves = Vec::new();
        for (index, (now, verdicts)) in observations.into_iter().enumerate() {
            seeded(&trace, &verdicts);
            let switch = selection.switched(&trace, select(&verdicts, now, HOLD));
            if index == 0 {
                continue;
            }
            if let Some(switch) = switch {
                moves.push(switch);
            }
        }
        assert_eq!(
            moves,
            vec![Switch {
                from: Some(written_as(F)),
                to: Some(written_as(P)),
                cause: SwitchCause::Held,
            }]
        );
    }

    #[test]
    fn each_row_of_the_switch_cause_table_names_its_cause() {
        let live = LiveUpstream::default();
        let list = published(&live, &[P, F]);
        let rows = [
            (
                "the carrying entry turned down",
                [down(secs(0)), up(secs(0))],
                Some(0),
                Some(1),
                SwitchCause::Down,
            ),
            (
                "the last up entry turned down",
                [down(secs(0)), down(secs(0))],
                Some(0),
                None,
                SwitchCause::Down,
            ),
            (
                "the primary held",
                [up(secs(0)), up(secs(0))],
                Some(1),
                Some(0),
                SwitchCause::Held,
            ),
            (
                "an entry came up from none",
                [down(secs(0)), up(secs(0))],
                None,
                Some(1),
                SwitchCause::Recovered,
            ),
        ];
        for (name, after, previous, new, expected) in rows {
            let selection = Selection::default();
            let _primed = selection.switched(&list, previous);
            seeded(&list, &after);

            let Some(Switch {
                from: _,
                to: _,
                cause,
            }) = selection.switched(&list, new)
            else {
                panic!("{name}: no switch logged");
            };

            assert_eq!(cause, expected, "{name}");
        }
    }

    #[test]
    fn a_reload_that_respells_the_selected_address_is_no_switch() {
        let live = LiveUpstream::default();
        let list = published(&live, &[P, F]);
        let selection = Selection::default();
        let _primed = selection.switched(&list, Some(0));
        let respelled =
            Upstreams::parse(UpstreamAddr(P.to_owned()), vec![UpstreamAddr(F.to_owned())]).unwrap();
        live.publish(&respelled);
        let respelled = live.snapshot();

        let switch = selection.switched(&respelled, Some(0));

        assert_eq!(switch, None);
    }

    #[test]
    fn a_selection_from_a_replaced_list_records_nothing() {
        let live = LiveUpstream::default();
        let replaced = published(&live, &[P, F]);
        let list = published(&live, &[F, G]);
        let selection = Selection::default();
        let _primed = selection.switched(&list, Some(1));

        let stale = selection.switched(&replaced, Some(0));
        let current = selection.switched(&list, Some(1));

        assert_eq!(stale, None);
        assert_eq!(current, None);
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct SwitchFields {
        upstream_from: String,
        upstream_to: String,
        switch_cause: SwitchCause,
    }

    #[test]
    fn a_switch_is_logged_once() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path());
        let subscriber = logging::subscriber(&paths).unwrap();
        let live = LiveUpstream::default();
        let list = published(&live, &[P, F]);
        list.as_slice()[1].health().seed(HealthState::Up);
        let selection = Selection::default();
        selection.observe(&list, None);
        let _silent = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());

        tracing::subscriber::with_default(subscriber, || {
            selection.observe(&list, Some(1));
            selection.observe(&list, Some(1));
        });

        let mut records = Vec::new();
        for file in logging::files(&paths).unwrap() {
            let (lines, _offset) = logging::read_from(&file, 0).unwrap();
            for line in lines {
                let line: serde_json::Value = serde_json::from_str(&line).unwrap();
                let fields = line.get("fields").unwrap().clone();
                records.push(serde_json::from_value::<SwitchFields>(fields).unwrap());
            }
        }
        assert_eq!(
            records,
            vec![SwitchFields {
                upstream_from: String::new(),
                upstream_to: format!("socks5://{F}"),
                switch_cause: SwitchCause::Recovered,
            }]
        );
    }
}
