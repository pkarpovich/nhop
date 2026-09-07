//! Wire contract shared by the `nhop` daemon and its command-line client.
//!
//! The daemon speaks newline-delimited JSON over a unix socket: one [`Command`] per line in, one
//! [`Response`] per line out, except [`Command::Subscribe`], which streams [`Response::Event`].

#![warn(missing_docs)]

mod command;
mod paths;
mod view;

pub use command::{
    Command, ErrKind, Host, InvalidLoadId, LOAD_ID_ENV, LoadId, Port, Response, RuleClass,
    RuleKind, RuleValue, UpstreamAddr,
};
pub use paths::{HomeNotFound, Paths};
pub use view::{
    CheckView, DecisionKind, DecisionView, EffectiveHop, EventView, HealthState, LastLoadView,
    LoadOutcome, RuleCountsView, RuleView, StatusView, SystemProxyView, Timestamp,
};
