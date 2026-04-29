pub mod business_entity;
pub mod create;
pub mod create_pop;
pub mod deactivate;
pub mod log;
pub mod update;
pub mod verify_pop;

use chrono::{DateTime, SecondsFormat};

/// Formats a Unix timestamp as a UTC ISO-8601 string with `Z` suffix
/// (e.g. `2026-04-29T18:23:00Z`). Falls back to the raw integer rendered as
/// a string if the timestamp is out of range.
pub(crate) fn iso8601(unix_secs: u64) -> String {
    DateTime::from_timestamp(unix_secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| unix_secs.to_string())
}
