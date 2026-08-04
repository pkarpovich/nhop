use nhop_ipc::{LoadId, RuleClass, RuleKind, RuleValue};

use crate::proxy::{Listen, Upstream};
use crate::rules::{InvalidRule, Ruleset};

/// Command an init run was rejected on, named as it appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedCommand {
    /// The value could not be read as its kind.
    AddRule,
    /// The address could not be read.
    SetUpstream,
    /// The front ends could not be moved to the address.
    SetListen,
}

impl FailedCommand {
    /// Returns the wire `cmd` string of the command.
    pub fn name(self) -> &'static str {
        match self {
            Self::AddRule => "add_rule",
            Self::SetUpstream => "set_upstream",
            Self::SetListen => "set_listen",
        }
    }
}

/// State a successful init run replaces the live state with.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Committed {
    /// Rules the run declared, in declaration order.
    pub rules: Ruleset,
    /// Upstream the run set, absent when it set none.
    pub upstream: Option<Upstream>,
    /// Front-end addresses the run set, absent when it set none.
    pub listen: Option<Listen>,
}

/// What one init run has built so far.
///
/// A run starts from nothing, so the init file always declares the whole rule set, and nothing it
/// stages reaches traffic until [`Staging::commit`] is called on a run that exited zero.
#[derive(Debug, Default)]
pub struct Staging {
    rules: Ruleset,
    upstream: Option<Upstream>,
    listen: Option<Listen>,
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

    /// Points the run at an upstream.
    pub fn set_upstream(&mut self, upstream: Upstream) {
        self.upstream = Some(upstream);
    }

    /// Moves the front ends the run commits.
    pub fn set_listen(&mut self, listen: Listen) {
        self.listen = Some(listen);
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
            failed: _,
        } = self;
        Committed {
            rules,
            upstream,
            listen,
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
    use nhop_ipc::{Host, Port, UpstreamAddr};

    use crate::rules::{Decision, RuleId};

    use super::*;

    fn value(value: &str) -> RuleValue {
        RuleValue(value.to_owned())
    }

    fn listen() -> Listen {
        Listen {
            http: "127.0.0.1:18080".parse().unwrap(),
            socks: "127.0.0.1:18081".parse().unwrap(),
        }
    }

    fn upstream(written: &str) -> Upstream {
        Upstream::parse(UpstreamAddr(written.to_owned())).unwrap()
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
        } = staging.commit();

        assert_eq!(rules.rules().len(), 2);
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
        staging.set_upstream(upstream("socks5://192.0.2.10:1080"));
        staging.set_listen(listen());
        staging.set_upstream(upstream("socks5://192.0.2.11:1080"));

        let Committed {
            rules: _,
            upstream: staged_upstream,
            listen: staged,
        } = staging.commit();

        assert_eq!(staged_upstream, Some(upstream("socks5://192.0.2.11:1080")));
        assert_eq!(staged, Some(listen()));
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
