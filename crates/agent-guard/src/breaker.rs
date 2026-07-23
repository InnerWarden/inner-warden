//! Cost / quota circuit breaker (OWASP Agentic **ASI09, Cost / Quota Abuse**).
//!
//! A hijacked or looping agent can bill you for an overnight retry storm: the
//! same sub-goal re-planned every iteration, each iteration a paid model call.
//! This breaker tracks cumulative spend and duplicate tool calls per agent run
//! and trips LOUD the moment either crosses a ceiling, so a runaway loop halts
//! instead of running up the bill. Pure and deterministic so it is exhaustively
//! unit-tested; the caller (the MCP proxy session / agent run loop) records each
//! tool call and honours a `Tripped` verdict by stopping the run.

use std::collections::HashMap;

/// Ceilings for a single agent run. Defaults match a conservative demo run.
#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// Halt once cumulative model spend for the run crosses this (USD).
    pub cost_ceiling_usd: f64,
    /// Halt once any identical tool call repeats more than this many times
    /// (a re-planning loop), regardless of spend.
    pub max_identical_calls: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            cost_ceiling_usd: 0.50,
            max_identical_calls: 3,
        }
    }
}

/// The breaker's decision after recording a call.
#[derive(Debug, Clone, PartialEq)]
pub enum BreakerVerdict {
    /// Run may continue.
    Ok,
    /// Run must halt; `reason` is the human-readable cause (mapped to ASI09).
    Tripped { reason: String },
}

impl BreakerVerdict {
    pub fn is_tripped(&self) -> bool {
        matches!(self, BreakerVerdict::Tripped { .. })
    }
}

/// Per-run cost + loop guard. One instance per agent run.
#[derive(Debug, Clone)]
pub struct Breaker {
    config: BreakerConfig,
    spent_usd: f64,
    counts: HashMap<String, u32>,
    tripped: bool,
}

impl Breaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            spent_usd: 0.0,
            counts: HashMap::new(),
            tripped: false,
        }
    }

    /// Total spend recorded so far (USD).
    pub fn spent_usd(&self) -> f64 {
        self.spent_usd
    }

    /// Record one tool/model call: its signature (tool name + salient args, so
    /// identical re-plans collide) and its cost in USD. Returns the verdict; once
    /// tripped it stays tripped (subsequent calls also return `Tripped`).
    pub fn record(&mut self, call_signature: &str, cost_usd: f64) -> BreakerVerdict {
        if self.tripped {
            return BreakerVerdict::Tripped {
                reason: "run already halted by the cost/quota breaker (ASI09)".into(),
            };
        }
        self.spent_usd += cost_usd.max(0.0);
        let n = self
            .counts
            .entry(call_signature.to_string())
            .and_modify(|c| *c += 1)
            .or_insert(1);
        let n = *n;

        if self.spent_usd > self.config.cost_ceiling_usd {
            self.tripped = true;
            return BreakerVerdict::Tripped {
                reason: format!(
                    "cost ceiling ${:.2} exceeded (spent ${:.2}), ASI09 Cost/Quota Abuse",
                    self.config.cost_ceiling_usd, self.spent_usd
                ),
            };
        }
        if n > self.config.max_identical_calls {
            self.tripped = true;
            return BreakerVerdict::Tripped {
                reason: format!(
                    "identical call repeated {n}x (>{} allowed), runaway loop, ASI09 Cost/Quota Abuse",
                    self.config.max_identical_calls
                ),
            };
        }
        BreakerVerdict::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_on_cost_ceiling() {
        let mut b = Breaker::new(BreakerConfig {
            cost_ceiling_usd: 0.50,
            max_identical_calls: 100,
        });
        assert_eq!(b.record("a", 0.30), BreakerVerdict::Ok);
        assert!(b.record("b", 0.30).is_tripped()); // 0.60 > 0.50
                                                   // stays tripped.
        assert!(b.record("c", 0.0).is_tripped());
    }

    #[test]
    fn trips_on_identical_call_loop() {
        let mut b = Breaker::new(BreakerConfig {
            cost_ceiling_usd: 100.0,
            max_identical_calls: 3,
        });
        for _ in 0..3 {
            assert_eq!(b.record("search(same)", 0.001), BreakerVerdict::Ok);
        }
        assert!(b.record("search(same)", 0.001).is_tripped()); // 4th identical
    }

    #[test]
    fn distinct_calls_do_not_trip_the_loop_guard() {
        let mut b = Breaker::new(BreakerConfig {
            cost_ceiling_usd: 100.0,
            max_identical_calls: 2,
        });
        for i in 0..10 {
            assert_eq!(b.record(&format!("call-{i}"), 0.001), BreakerVerdict::Ok);
        }
    }
}
