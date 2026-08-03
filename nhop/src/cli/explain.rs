use nhop_ipc::{DecisionKind, DecisionView, Host, Port, RuleView, UpstreamAddr};

use crate::rules::{Decision, RuleClass, RuleId, Ruleset};

/// Next hop reported for an upstream decision no init script has named an upstream for.
const NO_UPSTREAM: &str = "none";

/// Lists a ruleset in declaration order.
pub fn rule_views(rules: &Ruleset) -> Vec<RuleView> {
    let mut views = Vec::with_capacity(rules.rules().len());
    for rule in rules.rules() {
        views.push(RuleView {
            index: indexed(rule.id()),
            class: rule.class(),
            kind: rule.kind(),
            value: rule.value().clone(),
        });
    }
    views
}

/// Reports where a destination would be routed, without opening any connection.
pub fn decision_view(
    rules: &Ruleset,
    upstream: &UpstreamAddr,
    host: &Host,
    port: Port,
) -> DecisionView {
    match rules.decide(host, port) {
        Decision::Direct => DecisionView {
            decision: DecisionKind::Direct,
            rule_index: None,
            class: None,
            next_hop: dialled(host, port),
        },
        Decision::Never { rule } => DecisionView {
            decision: DecisionKind::Never,
            rule_index: Some(indexed(rule)),
            class: Some(RuleClass::Never),
            next_hop: dialled(host, port),
        },
        Decision::Upstream { class, rule } => match class {
            RuleClass::Require | RuleClass::Prefer => DecisionView {
                decision: DecisionKind::Upstream,
                rule_index: Some(indexed(rule)),
                class: Some(class),
                next_hop: named(upstream),
            },
            RuleClass::Never => DecisionView {
                decision: DecisionKind::Never,
                rule_index: Some(indexed(rule)),
                class: Some(class),
                next_hop: dialled(host, port),
            },
        },
    }
}

fn indexed(rule: RuleId) -> u32 {
    let RuleId(index) = rule;
    u32::try_from(index).unwrap_or(u32::MAX)
}

fn dialled(host: &Host, port: Port) -> String {
    let Host(host) = host;
    let Port(port) = port;
    if host.contains(':') {
        return format!("[{host}]:{port}");
    }
    format!("{host}:{port}")
}

fn named(upstream: &UpstreamAddr) -> String {
    let UpstreamAddr(upstream) = upstream;
    if upstream.is_empty() {
        return NO_UPSTREAM.to_owned();
    }
    upstream.clone()
}

#[cfg(test)]
mod tests {
    use nhop_ipc::{RuleKind, RuleValue};

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

    fn routed() -> Ruleset {
        ruleset(&[
            (RuleClass::Never, RuleKind::Suffix, "intranet.example.com"),
            (RuleClass::Require, RuleKind::Suffix, "example.com"),
            (RuleClass::Prefer, RuleKind::Port, "8443"),
        ])
    }

    fn upstream() -> UpstreamAddr {
        UpstreamAddr("socks5://192.0.2.10:1080".to_owned())
    }

    fn decide(host: &str, port: u16) -> DecisionView {
        decision_view(&routed(), &upstream(), &Host(host.to_owned()), Port(port))
    }

    #[test]
    fn a_require_match_is_handed_to_the_upstream() {
        assert_eq!(
            decide("api.example.com", 443),
            DecisionView {
                decision: DecisionKind::Upstream,
                rule_index: Some(1),
                class: Some(RuleClass::Require),
                next_hop: "socks5://192.0.2.10:1080".to_owned(),
            }
        );
    }

    #[test]
    fn a_prefer_match_is_handed_to_the_upstream() {
        assert_eq!(
            decide("example.net", 8443),
            DecisionView {
                decision: DecisionKind::Upstream,
                rule_index: Some(2),
                class: Some(RuleClass::Prefer),
                next_hop: "socks5://192.0.2.10:1080".to_owned(),
            }
        );
    }

    #[test]
    fn a_never_match_is_dialled_directly_and_says_which_rule_said_so() {
        assert_eq!(
            decide("intranet.example.com", 443),
            DecisionView {
                decision: DecisionKind::Never,
                rule_index: Some(0),
                class: Some(RuleClass::Never),
                next_hop: "intranet.example.com:443".to_owned(),
            }
        );
    }

    #[test]
    fn an_unmatched_destination_is_dialled_directly_by_no_rule() {
        assert_eq!(
            decide("example.net", 443),
            DecisionView {
                decision: DecisionKind::Direct,
                rule_index: None,
                class: None,
                next_hop: "example.net:443".to_owned(),
            }
        );
    }

    #[test]
    fn an_upstream_decision_without_an_upstream_names_none() {
        let decided = decision_view(
            &routed(),
            &UpstreamAddr(String::new()),
            &Host("api.example.com".to_owned()),
            Port(443),
        );
        assert_eq!(decided.next_hop, "none");
    }

    #[test]
    fn an_address_literal_is_dialled_as_it_would_be_written() {
        let decided = decision_view(
            &Ruleset::default(),
            &upstream(),
            &Host("2001:db8::1".to_owned()),
            Port(8443),
        );
        assert_eq!(decided.next_hop, "[2001:db8::1]:8443");
    }

    #[test]
    fn the_rules_are_listed_in_declaration_order() {
        assert_eq!(
            rule_views(&routed()),
            vec![
                RuleView {
                    index: 0,
                    class: RuleClass::Never,
                    kind: RuleKind::Suffix,
                    value: RuleValue("intranet.example.com".to_owned()),
                },
                RuleView {
                    index: 1,
                    class: RuleClass::Require,
                    kind: RuleKind::Suffix,
                    value: RuleValue("example.com".to_owned()),
                },
                RuleView {
                    index: 2,
                    class: RuleClass::Prefer,
                    kind: RuleKind::Port,
                    value: RuleValue("8443".to_owned()),
                },
            ]
        );
        assert!(rule_views(&Ruleset::default()).is_empty());
    }
}
