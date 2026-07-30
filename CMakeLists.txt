#
# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#

cmake_minimum_required(VERSION 3.26)
project(libghidra LANGUAGES CXX C)

# ============================================================================
# Options
# ============================================================================

option(LIBGHIDRA_WITH_LOCAL "Build the local (offline) backend" OFF)
option(LIBGHIDRA_BUILD_EXAMPLES "Build examples for all backends" OFF)

# Forward options into cpp/ subdirectory
if(LIBGHIDRA_WITH_LOCAL)
    set(LIBGHIDRA_WITH_LOCAL ON CACHE BOOL "" FORCE)
else()
    set(LIBGHIDRA_WITH_LOCAL OFF CACHE BOOL "" FORCE)
endif()

if(LIBGHIDRA_BUILD_EXAMPLES)
    set(LIBGHIDRA_BUILD_EXAMPLES ON CACHE BOOL "" FORCE)
endif()

# ============================================================================
# Single subdirectory: all C++ targets (libghidra_client + libghidra_local)
# ============================================================================

add_subdirectory(cpp)
