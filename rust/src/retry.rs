// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

use std::time::Duration;

use rand::Rng;

pub fn compute_backoff(
    attempt: u32,
    initial: Duration,
    max_backoff: Duration,
    jitter: bool,
) -> Duration {
    let base = initial.saturating_mul(1u32 << attempt.min(30));
    let base = base.min(max_backoff);
    if jitter {
        let lo = base * 3 / 4;
        let hi = base * 5 / 4;
        let ms = rand::rng().random_range(lo.as_millis()..=hi.as_millis());
        Duration::from_millis(ms as u64).min(max_backoff)
    } else {
        base
    }
}
