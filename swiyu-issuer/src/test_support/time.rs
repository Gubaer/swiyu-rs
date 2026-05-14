use chrono::{DateTime, Utc};

// Postgres TIMESTAMPTZ truncates to microseconds; rounding up front keeps the
// caller-supplied value equal to what a SELECT will return.
pub fn now_micros() -> DateTime<Utc> {
    let micros = Utc::now().timestamp_micros();
    DateTime::from_timestamp_micros(micros).unwrap()
}
