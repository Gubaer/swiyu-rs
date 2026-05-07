//! Retry-timing helpers for the operation-task worker.
//!
//! Exponential delay with full jitter, capped at 1 hour per attempt,
//! with a 24-hour wall-clock budget per task.

use std::time::Duration;

use rand_core::RngCore;

const BASE_MS: u64 = 60_000;
const MAX_MS: u64 = 3_600_000;

/// Wall-clock budget per task: once the task has been alive for at
/// least this many hours and the current step still asks for a retry,
/// the dispatcher escalates to `Failed` instead of scheduling another
/// attempt.
pub const MAX_TASK_AGE_HOURS: i64 = 24;

/// Returns the wait time before the next retry, drawn uniformly from
/// `[0, base * 2^attempts]` per AWS "exponential backoff with full
/// jitter". `base` is one minute; the per-attempt ceiling caps at one
/// hour.
///
/// `attempts` is the post-increment failure count for the current step
/// (`attempts == 1` after the first failure), matching how the worker
/// records the value before computing the delay.
pub fn backoff_delay<R: RngCore + ?Sized>(attempts: u32, rng: &mut R) -> Duration {
    // attempts >= 6 already exceeds the 1h ceiling (60_000 << 6 = 3_840_000 ms);
    // clamp to keep the shift safely inside u64 for any future growth in attempts.
    let effective_attempts = attempts.min(6);
    let ceiling_ms = (BASE_MS << effective_attempts).min(MAX_MS);
    // Modulo bias on a 64-bit RNG against a millisecond-scale ceiling is
    // far below the jitter resolution we need.
    let jitter_ms = rng.next_u64() % (ceiling_ms + 1);
    Duration::from_millis(jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u64);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.0 as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.0.to_le_bytes();
                let take = chunk.len().min(bytes.len());
                chunk[..take].copy_from_slice(&bytes[..take]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn first_attempt_caps_at_one_minute() {
        let delay = backoff_delay(0, &mut FixedRng(u64::MAX));
        assert!(delay <= Duration::from_secs(60), "{delay:?}");
    }

    #[test]
    fn second_attempt_caps_at_two_minutes() {
        let delay = backoff_delay(1, &mut FixedRng(u64::MAX));
        assert!(delay <= Duration::from_secs(120), "{delay:?}");
    }

    #[test]
    fn delay_caps_at_one_hour_for_high_attempt_counts() {
        for attempts in [6_u32, 10, 20, 100] {
            let delay = backoff_delay(attempts, &mut FixedRng(u64::MAX));
            assert!(
                delay <= Duration::from_secs(3600),
                "attempts={attempts}, delay={delay:?}",
            );
        }
    }

    #[test]
    fn rng_zero_yields_zero_delay() {
        for attempts in 0_u32..10 {
            assert_eq!(
                backoff_delay(attempts, &mut FixedRng(0)),
                Duration::from_millis(0),
                "attempts={attempts}",
            );
        }
    }

    #[test]
    fn jitter_uses_value_below_ceiling_unmodified() {
        // attempts=0 -> ceiling = 60_000 ms; an RNG value strictly below
        // the ceiling falls through the modulo unchanged.
        assert_eq!(
            backoff_delay(0, &mut FixedRng(30_001)),
            Duration::from_millis(30_001),
        );
    }
}
