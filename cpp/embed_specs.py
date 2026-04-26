#!/usr/bin/env python3
"""Generate C++ source with embedded Ghidra processor spec files.

Walks the Ghidra Processors directory and converts .sla, .pspec, .cspec,
and .ldefs files into zlib-compressed C byte arrays that can be compiled
into the library.  At runtime the library decompresses them on first use.

Usage:
    python embed_specs.py <ghidra_source_dir> <output_dir> [--processors x86,ARM,AARCH64]
"""

import argparse
import os
import sys
import zlib
import xml.etree.ElementTree as ET


SPEC_EXTENSIONS = {'.sla', '.pspec', '.cspec', '.ldefs'}


def sanitize_name(rel_path: str) -> str:
    """Convert a relative file path to a valid C identifier."""
    name = rel_path.replace('/', '_').replace('\\', '_').replace('.', '_')
    name = name.replace('-', '_').replace(' ', '_')
    # Strip leading underscores
    while name.startswith('_'):
        name = name[1:]
    return 'spec_' + name


def collect_spec_files(ghidra_src: str, processors: list[str] | None) -> list[tuple[str, str]]:
    """Collect (absolute_path, relative_path) pairs for all spec files.

    relative_path is relative to ghidra_src, preserving the directory structure
    that Ghidra's scanForSleighDirectories() expects.
    """
    processors_dir = os.path.join(ghidra_src, 'Ghidra', 'Processors')
    if not os.path.isdir(processors_dir):
        print(f"ERROR: Processors directory not found: {processors_dir}", file=sys.stderr)
        sys.exit(1)

    results = []
    for proc_name in sorted(os.listdir(processors_dir)):
        if processors and proc_name not in processors:
            continue
        lang_dir = os.path.join(processors_dir, proc_name, 'data', 'languages')
        if not os.path.isdir(lang_dir):
            continue
        for fname in sorted(os.listdir(lang_dir)):
            _, ext = os.path.splitext(fname)
            if ext.lower() in SPEC_EXTENSIONS:
                abs_path = os.path.join(lang_dir, fname)
                # Build relative path from ghidra_src root
                rel_path = os.path.relpath(abs_path, ghidra_src).replace('\\', '/')
                results.append((abs_path, rel_path))
    return results


def collect_language_index(specs: list[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    """Build a language -> compiler IDs index from collected .ldefs files."""
    languages = {}
    for abs_path, rel_path in specs:
        if not rel_path.lower().endswith('.ldefs'):
            continue
        try:
            tree = ET.parse(abs_path)
        except ET.ParseError as e:
            print(f"WARNING: failed to parse {rel_path}: {e}", file=sys.stderr)
            continue
        for lang in tree.getroot().findall('language'):
            lang_id = lang.attrib.get('id')
            if not lang_id:
                continue
            compilers = sorted({
                c.attrib.get('id', '')
                for c in lang.findall('compiler')
                if c.attrib.get('id')
            })
            languages[lang_id] = tuple(compilers)
    return languages


def write_python_language_index(languages: dict[str, tuple[str, ...]], output_path: str):
    """Write libghidra.known_languages as a small importable Python module."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('# Copyright (c) 2024-2026 Elias Bachaalany\n')
        f.write('# SPDX-License-Identifier: MPL-2.0\n')
        f.write('#\n')
        f.write('# This Source Code Form is subject to the terms of the Mozilla Public\n')
        f.write('# License, v. 2.0. If a copy of the MPL was not distributed with this\n')
        f.write('# file, You can obtain one at https://mozilla.org/MPL/2.0/.\n\n')
        f.write('"""Known Ghidra language and compiler IDs embedded with libghidra."""\n\n')
        f.write('from __future__ import annotations\n\n')
        f.write('# Generated from Ghidra processor *.ldefs files by cpp/embed_specs.py.\n')
        f.write('LANGUAGE_COMPILERS: dict[str, tuple[str, ...]] = {\n')
        for lang_id in sorted(languages):
            compilers = ', '.join(repr(c) for c in languages[lang_id])
            if compilers:
                compilers += ','
            f.write(f'    {lang_id!r}: ({compilers}),\n')
        f.write('}\n\n')
        f.write('LANGUAGE_IDS: frozenset[str] = frozenset(LANGUAGE_COMPILERS)\n')


def format_byte_array(data: bytes, line_width: int = 16) -> str:
    """Format raw bytes as a C initializer list."""
    lines = []
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        hex_vals = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'    {hex_vals},')
    return '\n'.join(lines)


def generate(
    ghidra_src: str,
    output_dir: str,
    processors: list[str] | None,
    python_output: str | None = None,
):
    specs = collect_spec_files(ghidra_src, processors)
    if not specs:
        print("WARNING: No spec files found!", file=sys.stderr)
    language_index = collect_language_index(specs)

    os.makedirs(output_dir, exist_ok=True)

    cpp_path = os.path.join(output_dir, 'embedded_specs.cpp')
    h_path = os.path.join(output_dir, 'embedded_specs.h')

    # --- Staleness check: skip regeneration if outputs are newer than all inputs ---
    if os.path.isfile(cpp_path) and os.path.isfile(h_path):
        output_mtime = min(os.path.getmtime(cpp_path), os.path.getmtime(h_path))
        script_mtime = os.path.getmtime(__file__)
        newest_input = script_mtime
        for abs_path, _ in specs:
            t = os.path.getmtime(abs_path)
            if t > newest_input:
                newest_input = t
        if newest_input < output_mtime:
            if python_output:
                write_python_language_index(language_index, python_output)
            print(f"Embedded specs up-to-date ({len(specs)} files), skipping generation.")
            return

    import hashlib
    total_original = 0
    total_compressed = 0
    # Compute a content-derived version key. Used by ghidra_cpp_init.cpp as
    # the per-build cache subdirectory name so that pip-upgrading to a wheel
    # whose embedded specs changed will invalidate ~/.ghidracpp/cache/sleigh
    # entries automatically. Hashing the (rel_path, raw bytes) pairs sorted
    # by rel_path guarantees the digest is identical iff the inputs are.
    digest = hashlib.sha256()
    for abs_path, rel_path in sorted(specs, key=lambda p: p[1]):
        with open(abs_path, 'rb') as sf:
            raw = sf.read()
        digest.update(rel_path.encode('utf-8'))
        digest.update(b'\0')
        digest.update(len(raw).to_bytes(8, 'little'))
        digest.update(raw)
    version_key = digest.hexdigest()[:16]

    # --- Generate .cpp ---
    with open(cpp_path, 'w') as f:
        f.write('// Auto-generated by embed_specs.py — do not edit\n')
        f.write('#include "embedded_specs.h"\n\n')
        f.write('namespace ghidra_embedded {\n\n')

        # Write each file as a zlib-compressed byte array
        entries = []  # (rel_path, var_name, compressed_size, original_size)
        for abs_path, rel_path in specs:
            with open(abs_path, 'rb') as sf:
                raw_data = sf.read()
            compressed = zlib.compress(raw_data, 9)
            total_original += len(raw_data)
            total_compressed += len(compressed)
            var_name = sanitize_name(rel_path)
            entries.append((rel_path, var_name, len(compressed), len(raw_data)))
            f.write(f'// {rel_path} ({len(raw_data)} -> {len(compressed)} bytes)\n')
            f.write(f'static const unsigned char {var_name}[] = {{\n')
            f.write(format_byte_array(compressed))
            f.write('\n};\n\n')

        # Write the registry array
        f.write('const EmbeddedSpec g_embedded_specs[] = {\n')
        for rel_path, var_name, comp_size, orig_size in entries:
            f.write(f'    {{ "{rel_path}", {var_name}, {comp_size}, {orig_size} }},\n')
        f.write('};\n\n')
        f.write(f'const int g_embedded_spec_count = {len(specs)};\n\n')
        f.write(f'const char* const g_embedded_specs_version = "{version_key}";\n\n')
        f.write('} // namespace ghidra_embedded\n')

    # --- Generate .h ---
    with open(h_path, 'w') as f:
        f.write('// Auto-generated by embed_specs.py — do not edit\n')
        f.write('#pragma once\n\n')
        f.write('#include <cstddef>\n\n')
        f.write('namespace ghidra_embedded {\n\n')
        f.write('struct EmbeddedSpec {\n')
        f.write('    const char* rel_path;       // e.g. "Ghidra/Processors/x86/data/languages/x86.sla"\n')
        f.write('    const unsigned char* data;   // zlib-compressed payload\n')
        f.write('    size_t compressed_size;\n')
        f.write('    size_t original_size;\n')
        f.write('};\n\n')
        f.write('extern const EmbeddedSpec g_embedded_specs[];\n')
        f.write('extern const int g_embedded_spec_count;\n')
        f.write('// 16-hex-char SHA-256 prefix of the embedded payload, content-derived.\n')
        f.write('// ghidra_cpp_init uses this as the cache version key so that wheel\n')
        f.write('// upgrades that change the spec contents force a fresh extraction.\n')
        f.write('extern const char* const g_embedded_specs_version;\n\n')
        f.write('} // namespace ghidra_embedded\n')

    ratio = (1.0 - total_compressed / total_original) * 100 if total_original else 0
    print(f"Generated {len(specs)} embedded specs")
    print(f"  Languages:  {len(language_index):,}")
    print(f"  Original:   {total_original:,} bytes")
    print(f"  Compressed: {total_compressed:,} bytes ({ratio:.1f}% reduction)")
    print(f"  {cpp_path}")
    print(f"  {h_path}")
    if python_output:
        write_python_language_index(language_index, python_output)
        print(f"  {python_output}")


def main():
    parser = argparse.ArgumentParser(description='Embed Ghidra spec files as C++ byte arrays')
    parser.add_argument('ghidra_source_dir', help='Path to Ghidra source tree')
    parser.add_argument('output_dir', help='Directory for generated files')
    parser.add_argument('--processors', default=None,
                        help='Comma-separated processor names to include (default: all)')
    parser.add_argument('--python-output', default=None,
                        help='Optional path for generated libghidra/known_languages.py')
    args = parser.parse_args()

    procs = None
    if args.processors and args.processors.upper() != 'ALL':
        procs = [p.strip() for p in args.processors.split(',') if p.strip()]

    generate(args.ghidra_source_dir, args.output_dir, procs, args.python_output)


if __name__ == '__main__':
    main()
