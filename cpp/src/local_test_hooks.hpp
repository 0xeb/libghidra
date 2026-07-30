// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// Test-only fault-injection seams for the local backend. Everything here is
// compiled ONLY when a regression-test build defines LIBGHIDRA_LOCAL_TEST_HOOKS
// (the same pattern as LIBGHIDRA_POOL_TEST_ACCESS in decompiler_pool.hpp); it
// is invisible to every production build.

#ifdef LIBGHIDRA_LOCAL_TEST_HOOKS

namespace libghidra::client::detail::testhooks {

// When set, invoked right after decompile_perform() has produced a live
// Funcdata* — the exact point the AnalysisCleanup RAII guard must cover — on
// the decompileWithLocals / applyLocalRename / applyLocalRetype paths. May
// throw to simulate a mid-path decompiler failure.
extern void (*post_decompile_fault)();

// Incremented after every Architecture::clearAnalysis() the AnalysisCleanup
// guard performs, so a test can prove the clear ran on an exception unwind.
extern int analysis_clear_count;

}  // namespace libghidra::client::detail::testhooks

#endif  // LIBGHIDRA_LOCAL_TEST_HOOKS
