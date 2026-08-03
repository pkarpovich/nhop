mod matcher;
mod ruleset;

pub use matcher::{InvalidRule, Keyword, Matcher, NormalizedHost, Suffix};
pub use nhop_ipc::{DecisionKind, Host, Port, RuleClass, RuleKind, RuleValue};
pub use ruleset::{Rule, Ruleset};

/// Position of a rule in declaration order, invalidated by the next load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleId(pub usize);

/// Where a destination is routed.
///
/// [`Decision::Direct`] and [`Decision::Never`] both dial the destination, and differ only in how
/// they are reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Dialled directly because no rule matched.
    Direct,
    /// Dialled directly because a `never` rule matched.
    Never {
        /// Rule that matched.
        rule: RuleId,
    },
    /// Handed to the upstream proxy.
    Upstream {
        /// Class of the rule that matched.
        class: RuleClass,
        /// Rule that matched.
        rule: RuleId,
    },
}

impl Decision {
    /// Returns how the decision is reported on the wire.
    pub fn kind(&self) -> DecisionKind {
        match self {
            Self::Direct => DecisionKind::Direct,
            Self::Never { rule: _ } => DecisionKind::Never,
            Self::Upstream { class: _, rule: _ } => DecisionKind::Upstream,
        }
    }

    /// Returns the rule that decided, absent when none matched.
    pub fn rule(&self) -> Option<RuleId> {
        match self {
            Self::Direct => None,
            Self::Never { rule } => Some(*rule),
            Self::Upstream { class: _, rule } => Some(*rule),
        }
    }

    /// Returns the class of the rule that decided, absent when none matched.
    pub fn class(&self) -> Option<RuleClass> {
        match self {
            Self::Direct => None,
            Self::Never { rule: _ } => Some(RuleClass::Never),
            Self::Upstream { class, rule: _ } => Some(*class),
        }
    }
}
