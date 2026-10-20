// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.
//
// The live host never shows the decompiler's plain text: it asks for markup
// (a token tree), rebuilds lines from the break tokens (DecompilerUtils.toLines)
// and prints them through PrettyPrinter with an IllegalCharCppTransformer. So a
// symbol like `filt$0` reads `filt_0` on the host while the offline plain
// printer kept the `$`. This file does the same walk over the same markup.

#include "host_print.h"

#include <algorithm>
#include <array>
#include <sstream>

#include "libdecomp.hh"
#include "../print_stream_guard.hpp"

using namespace ghidra;

namespace ghidra_standalone {

std::string sanitizeCppSymbol(const std::string& input) {
  enum : int { AFTER_FIRST_CHAR = 1, TEMPLATE = 2, OPERATOR = 4, FIRST_CHAR = 8 };
  static const std::array<int, 128> legal = [] {
    std::array<int, 128> t{};
    t['_'] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR | FIRST_CHAR;
    for (char d = '0'; d <= '9'; ++d) t[static_cast<unsigned char>(d)] = AFTER_FIRST_CHAR | TEMPLATE | OPERATOR;
    t['*'] = TEMPLATE | OPERATOR;
    t[':'] = TEMPLATE;
    t['('] = TEMPLATE | OPERATOR;
    t[')'] = TEMPLATE | OPERATOR;
    t['['] = TEMPLATE | OPERATOR;
    t[']'] = TEMPLATE | OPERATOR;
    t[','] = TEMPLATE;
    t['&'] = TEMPLATE | OPERATOR;
    for (char c : {'+', '-', '|', '=', '!', '/', '%', '^'}) t[static_cast<unsigned char>(c)] = OPERATOR;
    t['~'] = TEMPLATE | OPERATOR | FIRST_CHAR;
    return t;
  }();
  const bool is_operator = input.rfind("operator", 0) == 0;
  std::string out;
  out.reserve(input.size());
  int template_depth = 0;
  std::size_t index = 0;  // character (code point) index, as Java's char index
  for (std::size_t pos = 0; pos < input.size(); ++index) {
    const unsigned char c = static_cast<unsigned char>(input[pos]);
    if (c >= 0x80) {  // a whole UTF-8 sequence, kept
      std::size_t len = (c >> 5) == 0x6 ? 2 : (c >> 4) == 0xe ? 3 : (c >> 3) == 0x1e ? 4 : 1;
      len = std::min(len, input.size() - pos);
      out.append(input, pos, len);
      pos += len;
      continue;
    }
    bool ok = false;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
      ok = true;
    } else if (c == '<') {
      ++template_depth;
      ok = true;
    } else if (c == '>') {
      template_depth = template_depth > 0 ? template_depth - 1 : 0;
      ok = true;
    } else if (const int v = legal[c]; v != 0) {
      ok = ((v & AFTER_FIRST_CHAR) != 0 && index > 0) || ((v & FIRST_CHAR) != 0 && index == 0) ||
           ((v & TEMPLATE) != 0 && template_depth > 0) ||
           ((v & OPERATOR) != 0 && index >= 8 && index <= 10 && is_operator);
    }
    out += ok ? static_cast<char>(c) : '_';
    ++pos;
  }
  return out;
}

namespace {

// DecompilerUtils.toLines + PrettyPrinter.print over the markup stream.
class LineBuilder {
 public:
  void walk(Decoder& dec) {
    const uint4 elem = dec.openElement();
    std::string content;
    bool has_content = false;
    int4 indent = 0;
    uint4 color = Emit::no_color;
    for (;;) {
      const uint4 attrib = dec.getNextAttributeId();
      if (attrib == 0) break;
      if (attrib == ATTRIB_CONTENT) {
        content = dec.readString();
        has_content = true;
      } else if (attrib == ATTRIB_INDENT) {
        indent = static_cast<int4>(dec.readSignedInteger());
      } else if (attrib == ATTRIB_COLOR) {
        color = static_cast<uint4>(dec.readUnsignedInteger());
      }
    }
    if (elem == ELEM_BREAK) {
      lineBreak(indent);
    } else if (has_content) {
      // PrettyPrinter.getText: these token kinds go through the transformer,
      // except a variable token printed as a constant.
      const bool clean = elem == ELEM_FUNCNAME || elem == ELEM_TYPE || elem == ELEM_FIELD ||
                         elem == ELEM_LABEL ||
                         (elem == ELEM_VARIABLE && color != Emit::const_color);
      token(clean ? sanitizeCppSymbol(content) : content);
    }
    while (dec.peekElement() != 0) walk(dec);
    dec.closeElement(elem);
  }

  std::string finish() {
    if (!started_) return out_;
    endLine();
    return std::move(out_);
  }

 private:
  std::string out_;
  std::string line_;
  bool line_has_tokens_ = false;
  bool started_ = false;
  int4 indent_ = 0;

  void token(const std::string& text) {
    started_ = true;
    line_ += text;
    line_has_tokens_ = true;
  }

  void lineBreak(int4 indent) {
    if (started_) endLine();  // a leading break only sets the first line's indent
    started_ = true;
    indent_ = indent;
  }

  void endLine() {
    const std::string pad(static_cast<std::size_t>(indent_ > 0 ? indent_ : 0), ' ');
    out_ += pad;
    // padEmptyLines: an empty line holds a spacer token of the same indent.
    out_ += line_has_tokens_ ? line_ : pad;
    out_ += '\n';
    line_.clear();
    line_has_tokens_ = false;
  }
};

}  // namespace

std::string printFunctionLikeHost(Architecture* arch, Funcdata* fd) {
  std::ostringstream markup;
  arch->print->setMarkup(true);
  {
    libghidra::detail::ScopedPrintStream print_guard(arch->print, markup);
    arch->print->docFunction(fd);
  }
  std::istringstream in(markup.str());
  PackedDecode dec(arch);
  dec.ingestStream(in);
  LineBuilder lines;
  if (dec.peekElement() != 0) lines.walk(dec);
  return lines.finish();
}

}  // namespace ghidra_standalone
