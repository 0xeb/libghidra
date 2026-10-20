// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <string>

namespace ghidra {
class Architecture;
class Funcdata;
}  // namespace ghidra

namespace ghidra_standalone {

/// C text of a decompiled function, produced the way the live host produces it
/// (DecompileResults.getDecompiledFunction): the printer emits markup tokens,
/// lines are split at the break tokens with their indent, and the text of
/// function-name, variable (not constant), type, field and label tokens goes
/// through Ghidra's IllegalCharCppTransformer, so `filt$0` prints as `filt_0`.
/// Lines end in '\n'. `fd` must hold a completed decompilation.
std::string printFunctionLikeHost(ghidra::Architecture* arch, ghidra::Funcdata* fd);

/// Ghidra's IllegalCharCppTransformer.simplify(): every character that is not
/// legal in a C++ symbol at its position becomes '_'. Non-ASCII code points
/// are kept (Java keeps the letters among them; this port does not classify
/// Unicode).
std::string sanitizeCppSymbol(const std::string& name);

}  // namespace ghidra_standalone
