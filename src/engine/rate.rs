//! Token bucket rate limiting with fixed-point nanosecond credit replenishment.

use std::time::Duration;

/// Fixed-point scaling factor: one packet token equals 1,000,000,000 credit units.
const TOKEN_SCALE: u64 = 1_000_000_000;

/// Token bucket tracking packet allowance over time.
#[derive(Debug)]
pub(super) struct TokenBucket {
    /// Available credit in fractional token units.
    pub credit: u64,
    /// Timestamp of the most recent credit update.
    pub updated: Duration,
}

impl TokenBucket {
    /// Creates a bucket initialized to its maximum burst capacity.
    pub fn new(burst: u32) -> Self {
        Self {
            credit: u64::from(burst) * TOKEN_SCALE,
            updated: Duration::ZERO,
        }
    }

    /// Attempts to consume one packet token at timestamp `now`.
    ///
    /// Refills credit based on elapsed time at `rate` packets per second, capped
    /// at `burst` packets. Returns `true` if a token was available and consumed.
    pub fn try_consume(&mut self, now: Duration, rate: u32, burst: u32) -> bool {
        let capacity = u64::from(burst) * TOKEN_SCALE;
        let elapsed = now.saturating_sub(self.updated).as_nanos();
        let added = (elapsed * u128::from(rate)).min(u128::from(capacity)) as u64;
        self.credit = self.credit.saturating_add(added).min(capacity);
        self.updated = self.updated.max(now);
        if self.credit < TOKEN_SCALE {
            false
        } else {
            self.credit -= TOKEN_SCALE;
            true
        }
    }
}
