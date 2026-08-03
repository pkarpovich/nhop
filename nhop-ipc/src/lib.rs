//! Wire contract shared by the `nhop` daemon and its command-line client.
//!
//! The daemon speaks newline-delimited JSON over a unix socket: one [`Command`] per line in, one
//! [`Response`] per line out. [`Command::Subscribe`] is the sole exception and switches the
//! connection to a stream of [`Response::Event`] lines.

#![warn(missing_docs)]

mod command;
mod paths;
mod view;

pub use command::{
    Command, ErrKind, Host, LoadId, Port, Response, RuleClass, RuleKind, RuleValue, UpstreamAddr,
};
pub use paths::{HomeNotFound, Paths};
pub use view::{
    CheckView, DecisionKind, DecisionView, EventView, HealthState, LastLoadView, LoadOutcome,
    RuleCountsView, RuleView, StatusView, SystemProxyView, Timestamp,
};
