// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// Shared RAII guard for Ghidra's PrintLanguage output stream.
//
// The decompile idiom points `arch->print` at a stack-local std::ostringstream,
// runs docFunction(), then reads the string. Historically the stream pointer was
// left referencing that local after the scope exited — a dangling pointer that
// was "safe by luck" only because every subsequent user re-set the stream before
// use. This guard fixes the idiom at root: it resets the stream to a process-
// lifetime discard sink on scope exit, so `arch->print` is never left dangling.
//
// Templated on the print type so this header does not need the full Ghidra
// decompiler headers; the type is completed at the instantiation site (each
// translation unit already includes libdecomp.hh before using the guard).

#include <ostream>
#include <streambuf>

namespace libghidra::detail {

// Process-lifetime discard sink. Anything written here is dropped.
inline std::ostream& null_print_sink() {
  struct NullBuf : std::streambuf {
    int overflow(int c) override { return c; }
  };
  static NullBuf buf;
  static std::ostream os(&buf);
  return os;
}

template <typename PrintT>
class ScopedPrintStream {
 public:
  ScopedPrintStream(PrintT* print, std::ostream& target) : print_(print) {
    if (print_) print_->setOutputStream(&target);
  }
  ~ScopedPrintStream() {
    if (print_) print_->setOutputStream(&null_print_sink());
  }
  ScopedPrintStream(const ScopedPrintStream&) = delete;
  ScopedPrintStream& operator=(const ScopedPrintStream&) = delete;

 private:
  PrintT* print_;
};

}  // namespace libghidra::detail
