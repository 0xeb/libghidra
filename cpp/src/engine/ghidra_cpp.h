// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

/// \file ghidra_cpp.h
/// \brief Single public header for the ghidra_cpp library.
///
/// Consumers should include only this header:
///   #include "ghidra_cpp.h"
///
/// Link modes:
///   - Static: link ghidra_cpp.lib (on MSVC, WHOLE_ARCHIVE is handled automatically)
///   - DLL:    link the import .lib; ghidra_cpp.dll must be at runtime

#pragma once

// ============================================================================
// Export macro
// ============================================================================

#if defined(GHIDRA_CPP_SHARED)
    #if defined(_MSC_VER)
        #if defined(GHIDRA_CPP_BUILDING)
            #define GHIDRA_API __declspec(dllexport)
        #else
            #define GHIDRA_API __declspec(dllimport)
        #endif
    #elif defined(__GNUC__) || defined(__clang__)
        #define GHIDRA_API __attribute__((visibility("default")))
    #else
        #define GHIDRA_API
    #endif
#else
    #define GHIDRA_API
#endif

// ============================================================================
// MSVC static link: auto-apply WHOLE_ARCHIVE via pragma
// ============================================================================

#if defined(_MSC_VER) && !defined(GHIDRA_CPP_SHARED) && !defined(GHIDRA_CPP_BUILDING)
    #pragma comment(linker, "/WHOLEARCHIVE:ghidra_cpp.lib")
#endif

// ============================================================================
// Public API headers
// ============================================================================

#include "ghidra_decompiler.h"   // ghidra_standalone::Decompiler, FunctionInfo, etc.
#include "ghidra_project.h"      // ghidra_db::GhidraProject, ProjectData, etc.
