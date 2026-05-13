#![allow(dead_code)] // not every test module pulls in every helper

use chrono::{DateTime, Utc};

// Postgres TIMESTAMPTZ truncates to microseconds; rounding up front keeps the
// caller-supplied value equal to what a SELECT will return.
pub fn now_micros() -> DateTime<Utc> {
    let micros = Utc::now().timestamp_micros();
    DateTime::from_timestamp_micros(micros).unwrap()
}

// 1_768_982_400 = 2026-01-21T12:00:00Z.
pub fn fixture_now() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_768_982_400, 0).unwrap()
}
