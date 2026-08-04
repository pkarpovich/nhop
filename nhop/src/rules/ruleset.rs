use nhop_ipc::{Host, Port, RuleClass, RuleKind, RuleValue};

use crate::rules::matcher::{InvalidRule, Matcher, NormalizedHost};
use crate::rules::{Decision, RuleId};

/// One rule, as declared by the init script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    id: RuleId,
    class: RuleClass,
    matcher: Matcher,
    value: RuleValue,
}

impl Rule {
    /// Returns the position of the rule in declaration order.
    pub fn id(&self) -> RuleId {
        self.id
    }

    /// Returns how a matching connection is routed.
    pub fn class(&self) -> RuleClass {
        self.class
    }

    /// Returns what the rule matches on.
    pub fn kind(&self) -> RuleKind {
        self.matcher.kind()
    }

    /// Returns the value as the operator wrote it.
    pub fn value(&self) -> &RuleValue {
        &self.value
    }
}

/// Rules in declaration order, swapped in and out as one unit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ruleset {
    rules: Vec<Rule>,
}

impl Ruleset {
    /// Appends a rule and returns its position in declaration order.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRule`] and leaves the ruleset untouched.
    pub fn push(
        &mut self,
        class: RuleClass,
        kind: RuleKind,
        value: RuleValue,
    ) -> Result<RuleId, InvalidRule> {
        let matcher = Matcher::parse(kind, &value)?;
        let id = RuleId(self.rules.len());
        self.rules.push(Rule {
            id,
            class,
            matcher,
            value,
        });
        Ok(id)
    }

    /// Returns the rules in declaration order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns how many rules carry a given class.
    pub fn count(&self, class: RuleClass) -> usize {
        let mut count = 0;
        for rule in &self.rules {
            if rule.class == class {
                count += 1;
            }
        }
        count
    }

    /// Returns where a destination is routed.
    ///
    /// `never` rules are consulted first, then the rest in declaration order; first match wins.
    pub fn decide(&self, host: &Host, port: Port) -> Decision {
        let host = NormalizedHost::new(host);
        for rule in &self.rules {
            let Rule {
                id,
                class,
                matcher,
                value: _,
            } = rule;
            match class {
                RuleClass::Never => {}
                RuleClass::Require | RuleClass::Prefer => continue,
            }
            if matcher.matches(&host, port) {
                return Decision::Never { rule: *id };
            }
        }
        for rule in &self.rules {
            let Rule {
                id,
                class,
                matcher,
                value: _,
            } = rule;
            match class {
                RuleClass::Require | RuleClass::Prefer => {}
                RuleClass::Never => continue,
            }
            if matcher.matches(&host, port) {
                return Decision::Upstream {
                    class: *class,
                    rule: *id,
                };
            }
        }
        Decision::Direct
    }
}

#[cfg(test)]
mod tests {
    use nhop_ipc::DecisionKind;

    use super::*;

    fn ruleset(rules: &[(RuleClass, RuleKind, &str)]) -> Ruleset {
        let mut ruleset = Ruleset::default();
        for (class, kind, value) in rules {
            ruleset
                .push(*class, *kind, RuleValue((*value).to_owned()))
                .unwrap();
        }
        ruleset
    }

    fn decide(ruleset: &Ruleset, host: &str, port: u16) -> Decision {
        ruleset.decide(&Host(host.to_owned()), Port(port))
    }

    #[test]
    fn an_empty_ruleset_dials_directly() {
        let ruleset = Ruleset::default();
        assert_eq!(decide(&ruleset, "example.com", 443), Decision::Direct);
    }

    #[test]
    fn an_unmatched_destination_dials_directly() {
        let ruleset = ruleset(&[(RuleClass::Require, RuleKind::Suffix, "example.com")]);
        assert_eq!(decide(&ruleset, "example.net", 443), Decision::Direct);
    }

    #[test]
    fn push_numbers_rules_in_declaration_order() {
        let mut ruleset = Ruleset::default();
        let first = ruleset
            .push(
                RuleClass::Require,
                RuleKind::Suffix,
                RuleValue("example.com".to_owned()),
            )
            .unwrap();
        let second = ruleset
            .push(
                RuleClass::Prefer,
                RuleKind::Port,
                RuleValue("443".to_owned()),
            )
            .unwrap();
        assert_eq!(first, RuleId(0));
        assert_eq!(second, RuleId(1));
        assert_eq!(ruleset.rules().len(), 2);
    }

    #[test]
    fn a_rejected_rule_leaves_the_ruleset_untouched() {
        let mut ruleset = ruleset(&[(RuleClass::Require, RuleKind::Suffix, "example.com")]);
        let failure = ruleset
            .push(
                RuleClass::Prefer,
                RuleKind::Port,
                RuleValue("80-90".to_owned()),
            )
            .unwrap_err();
        assert_eq!(failure.err_kind(), nhop_ipc::ErrKind::InvalidArgs);
        assert_eq!(ruleset.rules().len(), 1);
        assert_eq!(
            decide(&ruleset, "example.com", 80),
            Decision::Upstream {
                class: RuleClass::Require,
                rule: RuleId(0),
            }
        );
    }

    #[test]
    fn rules_report_their_kind_class_and_original_value() {
        let ruleset = ruleset(&[(RuleClass::Never, RuleKind::Suffix, "Example.COM.")]);
        let [rule] = ruleset.rules() else {
            panic!("expected one rule");
        };
        assert_eq!(rule.id(), RuleId(0));
        assert_eq!(rule.class(), RuleClass::Never);
        assert_eq!(rule.kind(), RuleKind::Suffix);
        assert_eq!(rule.value(), &RuleValue("Example.COM.".to_owned()));
    }

    #[test]
    fn count_reports_rules_per_class() {
        let ruleset = ruleset(&[
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Prefer, RuleKind::Port, "443"),
            (RuleClass::Prefer, RuleKind::Keyword, "cdn"),
            (RuleClass::Never, RuleKind::Cidr, "192.0.2.0/24"),
        ]);
        assert_eq!(ruleset.count(RuleClass::Require), 1);
        assert_eq!(ruleset.count(RuleClass::Prefer), 2);
        assert_eq!(ruleset.count(RuleClass::Never), 1);
    }

    #[test]
    fn never_rules_win_over_earlier_rules() {
        let ruleset = ruleset(&[
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Never, RuleKind::Suffix, "api.example.com"),
        ]);
        assert_eq!(
            decide(&ruleset, "api.example.com", 443),
            Decision::Never { rule: RuleId(1) }
        );
        assert_eq!(
            decide(&ruleset, "www.example.com", 443),
            Decision::Upstream {
                class: RuleClass::Require,
                rule: RuleId(0),
            }
        );
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let ruleset = ruleset(&[
            (RuleClass::Prefer, RuleKind::Port, "443"),
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
        ]);
        assert_eq!(
            decide(&ruleset, "example.com", 443),
            Decision::Upstream {
                class: RuleClass::Prefer,
                rule: RuleId(0),
            }
        );
        assert_eq!(
            decide(&ruleset, "example.com", 80),
            Decision::Upstream {
                class: RuleClass::Require,
                rule: RuleId(1),
            }
        );
    }

    #[test]
    fn a_never_rule_declared_first_still_wins() {
        let ruleset = ruleset(&[
            (RuleClass::Never, RuleKind::Cidr, "192.0.2.0/24"),
            (RuleClass::Require, RuleKind::Port, "443"),
        ]);
        assert_eq!(
            decide(&ruleset, "192.0.2.9", 443),
            Decision::Never { rule: RuleId(0) }
        );
    }

    #[test]
    fn decisions_report_their_rule_and_class() {
        let ruleset = ruleset(&[
            (RuleClass::Never, RuleKind::Suffix, "intranet.example.com"),
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
        ]);

        let decision = decide(&ruleset, "intranet.example.com", 443);
        assert_eq!(decision.kind(), DecisionKind::Never);
        assert_eq!(decision.rule(), Some(RuleId(0)));
        assert_eq!(decision.class(), Some(RuleClass::Never));

        let decision = decide(&ruleset, "www.example.com", 443);
        assert_eq!(decision.kind(), DecisionKind::Upstream);
        assert_eq!(decision.rule(), Some(RuleId(1)));
        assert_eq!(decision.class(), Some(RuleClass::Require));

        let decision = decide(&ruleset, "example.net", 443);
        assert_eq!(decision.kind(), DecisionKind::Direct);
        assert_eq!(decision.rule(), None);
        assert_eq!(decision.class(), None);
    }
}
