use nhop_ipc::{LoadId, RuleClass, RuleKind, RuleValue, UpstreamAddr};

use crate::proxy::{DuplicateForward, Forward, Forwards, Listen, UnusableUpstreams, Upstreams};
use crate::rules::{InvalidRule, Ruleset};

/// Command an init run was rejected on, named as it appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedCommand {
    /// The value could not be read as its kind.
    AddRule,
    /// The single upstream could not be read.
    SetUpstream,
    /// An address of a list with fallbacks could not be read, or was listed twice.
    SetUpstreams,
    /// The front ends could not be moved to the address.
    SetListen,
    /// The address was declared twice, or could not be bound.
    AddForward,
}

impl FailedCommand {
    /// Returns the wire `cmd` string of the command.
    pub fn name(self) -> &'static str {
        match self {
            Self::AddRule => "add_rule",
            Self::SetUpstream => "set_upstream",
            Self::SetUpstreams => "set_upstreams",
            Self::SetListen => "set_listen",
            Self::AddForward => "add_forward",
        }
    }
}

/// State a successful init run replaces the live state with.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Committed {
    /// Rules the run declared, in declaration order.
    pub rules: Ruleset,
    /// Upstreams the run set, absent when it set none.
    pub upstream: Option<Upstreams>,
    /// Front-end addresses the run set, absent when it set none.
    pub listen: Option<Listen>,
    /// Forwards the run declared, in declaration order.
    pub forwards: Forwards,
}

/// What one init run has built so far.
///
/// A run starts from nothing, so the init file always declares the whole rule set and the whole
/// set of forwards, and nothing it stages reaches traffic until [`Staging::commit`] is called on
/// a run that exited zero.
#[derive(Debug, Default)]
pub struct Staging {
    rules: Ruleset,
    upstream: Option<Upstreams>,
    listen: Option<Listen>,
    forwards: Forwards,
    failed: Option<FailedCommand>,
}

impl Staging {
    /// Appends a rule to the run.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRule`] when the value cannot be read as its kind, and marks the run as
    /// failed so that it is discarded even if the script goes on to exit zero.
    pub fn push_rule(
        &mut self,
        class: RuleClass,
        kind: RuleKind,
        value: RuleValue,
    ) -> Result<(), InvalidRule> {
        let Err(failure) = self.rules.push(class, kind, value) else {
            return Ok(());
        };
        self.fail(FailedCommand::AddRule);
        Err(failure)
    }

    /// Drops every rule staged so far.
    pub fn clear_rules(&mut self) {
        self.rules = Ruleset::default();
    }

    /// Points the run at an ordered list of upstreams, replacing any list staged before it.
    ///
    /// # Errors
    ///
    /// Returns [`UnusableUpstreams`] when an address cannot be read or is listed twice, and marks
    /// the run as failed so that it is discarded even if the script goes on to exit zero. The run
    /// fails on `set_upstream` for one address and on `set_upstreams` for a list, the command
    /// [`nhop_ipc::Command::upstreams`] sends for each.
    pub fn set_upstream(
        &mut self,
        first: UpstreamAddr,
        fallbacks: Vec<UpstreamAddr>,
    ) -> Result<(), UnusableUpstreams> {
        let sent = match fallbacks.is_empty() {
            true => FailedCommand::SetUpstream,
            false => FailedCommand::SetUpstreams,
        };
        let upstreams = match Upstreams::parse(first, fallbacks) {
            Ok(upstreams) => upstreams,
            Err(failure) => {
                self.fail(sent);
                return Err(failure);
            }
        };
        self.upstream = Some(upstreams);
        Ok(())
    }

    /// Moves the front ends the run commits.
    pub fn set_listen(&mut self, listen: Listen) {
        self.listen = Some(listen);
    }

    /// Appends a forward to the run.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateForward`] when the run already declares the address, and marks the run
    /// as failed so that it is discarded even if the script goes on to exit zero.
    pub fn push_forward(&mut self, forward: Forward) -> Result<(), DuplicateForward> {
        let Err(failure) = self.forwards.push(forward) else {
            return Ok(());
        };
        self.fail(FailedCommand::AddForward);
        Err(failure)
    }

    /// Returns the command the run was rejected on, absent while it is still viable.
    pub fn failure(&self) -> Option<FailedCommand> {
        self.failed
    }

    /// Returns the state the run replaces the live state with.
    pub fn commit(self) -> Committed {
        let Self {
            rules,
            upstream,
            listen,
            forwards,
            failed: _,
        } = self;
        Committed {
            rules,
            upstream,
            listen,
            forwards,
        }
    }

    /// Marks the run as failed, keeping the command it was first rejected on.
    pub fn fail(&mut self, command: FailedCommand) {
        match self.failed {
            Some(_first) => {}
            None => self.failed = Some(command),
        }
    }
}

/// Source of the identifier each init run is tagged with.
#[derive(Debug, Default)]
pub struct LoadIds(u64);

impl LoadIds {
    /// Returns an identifier no earlier run has carried.
    pub fn issue(&mut self) -> LoadId {
        let Self(issued) = self;
        *issued += 1;
        LoadId(*issued)
    }
}

#[cfg(test)]
mod tests {
    use nhop_ipc::{Host, Port};

    use crate::proxy::{DuplicateUpstream, Target};
    use crate::rules::{Decision, RuleId};

    use super::*;

    fn value(value: &str) -> RuleValue {
        RuleValue(value.to_owned())
    }

    fn forward(listen: &str, host: &str) -> Forward {
        Forward {
            listen: listen.parse().unwrap(),
            target: Target {
                host: Host(host.to_owned()),
                port: Port(9000),
            },
        }
    }

    fn listen() -> Listen {
        Listen {
            http: "127.0.0.1:18080".parse().unwrap(),
            socks: "127.0.0.1:18081".parse().unwrap(),
        }
    }

    fn addr(written: &str) -> UpstreamAddr {
        UpstreamAddr(written.to_owned())
    }

    fn upstreams(first: &str, fallbacks: &[&str]) -> Upstreams {
        let mut rest = Vec::new();
        for written in fallbacks {
            rest.push(addr(written));
        }
        Upstreams::parse(addr(first), rest).unwrap()
    }

    #[test]
    fn a_fresh_run_stages_nothing() {
        let staging = Staging::default();
        assert_eq!(staging.failure(), None);
        assert_eq!(staging.commit(), Committed::default());
    }

    #[test]
    fn staged_rules_keep_their_declaration_order() {
        let mut staging = Staging::default();
        staging
            .push_rule(RuleClass::Require, RuleKind::Suffix, value("example.com"))
            .unwrap();
        staging
            .push_rule(RuleClass::Never, RuleKind::Port, value("22"))
            .unwrap();

        let Committed {
            rules,
            upstream,
            listen,
            forwards,
        } = staging.commit();

        assert_eq!(rules.rules().len(), 2);
        assert_eq!(forwards, Forwards::default());
        assert_eq!(
            rules.decide(&Host("example.com".to_owned()), Port(443)),
            Decision::Upstream {
                class: RuleClass::Require,
                rule: RuleId(0),
            }
        );
        assert_eq!(upstream, None);
        assert_eq!(listen, None);
    }

    #[test]
    fn clearing_drops_the_rules_staged_so_far() {
        let mut staging = Staging::default();
        staging
            .push_rule(RuleClass::Require, RuleKind::Suffix, value("example.com"))
            .unwrap();

        staging.clear_rules();

        assert!(staging.commit().rules.rules().is_empty());
    }

    #[test]
    fn a_rejected_rule_fails_the_run_and_the_first_rejection_is_the_one_reported() {
        let mut staging = Staging::default();
        let failure = staging
            .push_rule(RuleClass::Require, RuleKind::Port, value("80-90"))
            .unwrap_err();
        assert_eq!(failure.err_kind(), nhop_ipc::ErrKind::InvalidArgs);
        assert_eq!(staging.failure(), Some(FailedCommand::AddRule));

        staging
            .push_rule(RuleClass::Require, RuleKind::Cidr, value("nonsense"))
            .unwrap_err();

        assert_eq!(staging.failure(), Some(FailedCommand::AddRule));
        assert_eq!(FailedCommand::AddRule.name(), "add_rule");
    }

    #[test]
    fn the_upstream_and_the_listen_addresses_travel_with_the_run() {
        let mut staging = Staging::default();
        staging
            .set_upstream(addr("socks5://192.0.2.10:1080"), Vec::new())
            .unwrap();
        staging.set_listen(listen());
        staging
            .set_upstream(addr("socks5://192.0.2.11:1080"), Vec::new())
            .unwrap();

        let Committed {
            rules: _,
            upstream: staged_upstream,
            listen: staged,
            forwards: _,
        } = staging.commit();

        assert_eq!(
            staged_upstream,
            Some(upstreams("socks5://192.0.2.11:1080", &[]))
        );
        assert_eq!(staged, Some(listen()));
    }

    #[test]
    fn a_second_upstream_line_replaces_the_whole_list() {
        let mut staging = Staging::default();
        staging
            .set_upstream(
                addr("socks5://192.0.2.10:1080"),
                vec![
                    addr("socks5://192.0.2.11:1080"),
                    addr("socks5://192.0.2.12:1080"),
                ],
            )
            .unwrap();
        staging
            .set_upstream(
                addr("socks5://192.0.2.20:1080"),
                vec![addr("socks5://192.0.2.10:1080")],
            )
            .unwrap();

        let Committed {
            rules: _,
            upstream,
            listen: _,
            forwards: _,
        } = staging.commit();

        assert_eq!(
            upstream,
            Some(upstreams(
                "socks5://192.0.2.20:1080",
                &["socks5://192.0.2.10:1080"]
            ))
        );
    }

    #[test]
    fn a_repeated_upstream_address_fails_the_command() {
        let mut staging = Staging::default();
        staging
            .set_upstream(addr("socks5://192.0.2.10:1080"), Vec::new())
            .unwrap();

        let refused = staging
            .set_upstream(
                addr("socks5://192.0.2.11:1080"),
                vec![addr("socks5://192.0.2.12:1080"), addr("192.0.2.11:1080")],
            )
            .unwrap_err();

        assert_eq!(
            refused,
            UnusableUpstreams::Duplicate(DuplicateUpstream("192.0.2.11:1080".parse().unwrap()))
        );
        assert!(refused.to_string().contains("192.0.2.11:1080"), "{refused}");
        assert_eq!(staging.failure(), Some(FailedCommand::SetUpstreams));
        let Committed {
            rules: _,
            upstream,
            listen: _,
            forwards: _,
        } = staging.commit();
        assert_eq!(upstream, Some(upstreams("socks5://192.0.2.10:1080", &[])));
    }

    #[test]
    fn an_unreadable_fallback_fails_the_command() {
        let mut staging = Staging::default();

        let refused = staging
            .set_upstream(
                addr("socks5://192.0.2.10:1080"),
                vec![addr("socks5://fallback.example.com:1080")],
            )
            .unwrap_err();

        assert!(
            refused.to_string().contains("fallback.example.com"),
            "{refused}"
        );
        assert_eq!(staging.failure(), Some(FailedCommand::SetUpstreams));
        assert_eq!(FailedCommand::SetUpstreams.name(), "set_upstreams");
    }

    #[test]
    fn staged_forwards_keep_their_declaration_order() {
        let mut staging = Staging::default();
        staging
            .push_forward(forward("127.0.0.1:19000", "one.example.com"))
            .unwrap();
        staging
            .push_forward(forward("127.0.0.1:19001", "two.example.com"))
            .unwrap();

        let Committed {
            rules: _,
            upstream: _,
            listen: _,
            forwards,
        } = staging.commit();

        assert_eq!(
            forwards.as_slice(),
            &[
                forward("127.0.0.1:19000", "one.example.com"),
                forward("127.0.0.1:19001", "two.example.com"),
            ]
        );
    }

    #[test]
    fn a_forward_declared_twice_fails_the_run_on_add_forward() {
        let mut staging = Staging::default();
        staging
            .push_forward(forward("127.0.0.1:19000", "one.example.com"))
            .unwrap();

        let refused = staging
            .push_forward(forward("127.0.0.1:19000", "two.example.com"))
            .unwrap_err();

        assert!(refused.to_string().contains("127.0.0.1:19000"), "{refused}");
        assert_eq!(staging.failure(), Some(FailedCommand::AddForward));
        assert_eq!(FailedCommand::AddForward.name(), "add_forward");
    }

    #[test]
    fn a_command_can_fail_a_run_the_staging_itself_did_not_reject() {
        let mut staging = Staging::default();
        staging.fail(FailedCommand::SetUpstream);
        staging.fail(FailedCommand::SetListen);

        assert_eq!(staging.failure(), Some(FailedCommand::SetUpstream));
        assert_eq!(FailedCommand::SetUpstream.name(), "set_upstream");
        assert_eq!(FailedCommand::SetListen.name(), "set_listen");
    }

    #[test]
    fn every_run_carries_an_identifier_of_its_own() {
        let mut ids = LoadIds::default();
        assert_eq!(ids.issue(), LoadId(1));
        assert_eq!(ids.issue(), LoadId(2));
        assert_eq!(ids.issue(), LoadId(3));
    }
}
