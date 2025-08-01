#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![deny(clippy::empty_docs)]
#![deny(clippy::empty_line_after_doc_comments)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unnecessary_safety_doc)]
#![deny(missing_docs)]

pub mod scheduler;

mod check;
mod discovery_registry;
mod error;
mod item;
mod result;
mod runner;
mod status;

pub use check::{AsyncCheck, Check, CheckHint, CheckMetadata};
pub use discovery_registry::DiscoveryRegistry;
pub use error::Error;
pub use item::Item;
pub use result::CheckResult;
pub use runner::{async_auto_fix, async_run, auto_fix, run};
pub use status::Status;
