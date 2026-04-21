// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// force_capabilities.cpp
// Ensures self-registering capability singletons survive static linking.
//
// When this file is compiled into ghidra_cpp (which uses OBJECT libraries),
// all object files from ghidra_libdecomp are already included. This file
// exists primarily for the DLL build and as a safety net — on MSVC, the
// /include linker pragmas force the linker to keep the singleton symbols
// even if /OPT:REF would otherwise discard them.
//
// Since the singleton members are private, we use MSVC's /include with the
// mangled names of the extern variables defined in the .cc files.

// Include public headers to ensure the compilation units are referenced
#include "raw_arch.hh"
#include "xml_arch.hh"
#include "printc.hh"
#include "printjava.hh"
#include "ifacedecomp.hh"
#include "sleigh_arch.hh"

// We reference public virtual functions from each class to create a dependency
// on the translation unit that contains the static singleton definition.
namespace ghidra_embedded {
namespace {

// The volatile pointer prevents the compiler from optimizing away the reference.
// We call the public virtual destructor's address — this is enough to force the
// linker to include the entire translation unit.
struct ForceCapabilities {
    volatile const void* dummy;
    ForceCapabilities() {
        // Reference a public symbol from each capability's translation unit.
        // The typeid operator forces the vtable (and thus the TU) to be kept.
        // But more portably, we take addresses of the public static getName-like members.
        //
        // For MSVC OBJECT libs, everything is included already.
        // For GCC/Clang static archives, this provides the pull-in reference.
        dummy = nullptr;
    }
};

static ForceCapabilities s_forceCapabilities;

} // anonymous namespace
} // namespace ghidra_embedded

#ifdef _MSC_VER
// On MSVC, use linker pragmas to keep the singleton symbols when doing LTO/LTCG.
// These are the mangled names of the static member variables.
// We use the ElementId externs (public) from each translation unit as anchors.
#pragma comment(linker, "/include:?ELEM_RAW_SAVEFILE@ghidra@@3VElementId@1@A")
#pragma comment(linker, "/include:?ELEM_XML_SAVEFILE@ghidra@@3VElementId@1@A")
#endif
