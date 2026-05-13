#![allow(dead_code)] // not every test module pulls in every helper

use chrono::{DateTime, Utc};

/// Postgres `TIMESTAMPTZ` keeps microsecond precision. `Utc::now()`
/// produces nanoseconds, which round-trip through the database as
/// truncated values and break direct equality assertions on what the
/// caller passed in. Tests round to microseconds up front so the
/// asserted timestamp is exactly what the row will hold.
pub fn now_micros() -> DateTime<Utc> {
    let micros = Utc::now().timestamp_micros();
    DateTime::from_timestamp_micros(micros).unwrap()
}
