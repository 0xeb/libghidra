// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "ghidra_cpp_init.h"
#include "embedded_specs.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#include "zlib.h"

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <cstring>
#endif

namespace ghidra_embedded {

namespace {

std::mutex g_mutex;
int g_refcount = 0;
std::string g_spec_dir;

// ---------------------------------------------------------------------------
// Platform helpers
// ---------------------------------------------------------------------------

bool makeDir(const std::string& path) {
#ifdef _WIN32
    return _mkdir(path.c_str()) == 0 || errno == EEXIST;
#else
    return mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

bool makeDirsRecursive(const std::string& path) {
    if (path.empty()) return true;
    if (makeDir(path)) return true;
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos && pos > 0) {
        if (!makeDirsRecursive(path.substr(0, pos)))
            return false;
    }
    return makeDir(path);
}

void removeRecursive(const std::string& path) {
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    std::string search = path + "\\*";
    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            std::string child = path + "\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                removeRecursive(child);
            } else {
                DeleteFileA(child.c_str());
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(path.c_str());
#else
    DIR* dir = opendir(path.c_str());
    if (!dir) {
        remove(path.c_str());
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        std::string child = path + "/" + entry->d_name;
        struct stat st;
        if (stat(child.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            removeRecursive(child);
        } else {
            remove(child.c_str());
        }
    }
    closedir(dir);
    rmdir(path.c_str());
#endif
}

// ---------------------------------------------------------------------------
// Cache directory: ~/.ghidracpp/cache/sleigh/
// ---------------------------------------------------------------------------

std::string getUserCacheDir() {
#ifdef _WIN32
    const char* home = std::getenv("USERPROFILE");
    if (!home || !home[0]) home = "C:\\";
    return std::string(home) + "\\.ghidracpp\\cache\\sleigh";
#else
    const char* home = std::getenv("HOME");
    if (!home || !home[0]) home = "/tmp";
    return std::string(home) + "/.ghidracpp/cache/sleigh";
#endif
}

// ---------------------------------------------------------------------------
// Version key: 16-hex-char SHA-256 prefix of the embedded-specs payload,
// computed at build time by embed_specs.py and emitted into embedded_specs.cpp
// as g_embedded_specs_version. Hashing the payload (not /proc/self/exe or
// GetModuleFileNameA(NULL,...)) means the cache invalidates iff the *embedded
// content* actually changed — pip-upgrading to a wheel with the same specs
// reuses the cache, while a rebuild that picks up updated Sleigh data forces
// a fresh extraction. Previously this hashed python.exe's mtime (because
// GetModuleFileNameA(NULL, ...) returns the host process path on Windows),
// which never changed across libghidra wheel upgrades and led to stale spec
// caches.
// ---------------------------------------------------------------------------

std::string getVersionKey() {
    return std::string(g_embedded_specs_version);
}

// ---------------------------------------------------------------------------
// Decompress + write a single spec file
// ---------------------------------------------------------------------------

bool decompressAndWrite(const EmbeddedSpec& spec, const std::string& dest_dir) {
    std::string full_path = dest_dir + "/" + spec.rel_path;

    // Ensure parent directory exists
    size_t last_sep = full_path.find_last_of("/\\");
    if (last_sep != std::string::npos) {
        if (!makeDirsRecursive(full_path.substr(0, last_sep))) {
            fprintf(stderr, "ghidra_cpp: failed to create directory for %s\n",
                    spec.rel_path);
            return false;
        }
    }

    // Decompress using inflate (Ghidra's bundled zlib doesn't include uncompress.c)
    std::vector<unsigned char> out_buf(spec.original_size);

    z_stream strm = {};
    strm.next_in = const_cast<Bytef*>(spec.data);
    strm.avail_in = static_cast<uInt>(spec.compressed_size);
    strm.next_out = out_buf.data();
    strm.avail_out = static_cast<uInt>(spec.original_size);

    int zret = inflateInit(&strm);
    if (zret != Z_OK) {
        fprintf(stderr, "ghidra_cpp: inflateInit failed (%d) for %s\n",
                zret, spec.rel_path);
        return false;
    }
    zret = inflate(&strm, Z_FINISH);
    uLong dest_len = strm.total_out;
    inflateEnd(&strm);
    if (zret != Z_STREAM_END) {
        fprintf(stderr, "ghidra_cpp: inflate failed (%d) for %s\n",
                zret, spec.rel_path);
        return false;
    }

    // Write decompressed data
    std::ofstream out(full_path, std::ios::binary);
    if (!out) {
        fprintf(stderr, "ghidra_cpp: failed to write %s\n", full_path.c_str());
        return false;
    }
    out.write(reinterpret_cast<const char*>(out_buf.data()),
              static_cast<std::streamsize>(dest_len));
    if (!out) {
        fprintf(stderr, "ghidra_cpp: write error for %s\n", full_path.c_str());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Extract all specs to cache dir
// ---------------------------------------------------------------------------

bool extractSpecs(const std::string& dest_dir) {
    for (int i = 0; i < g_embedded_spec_count; ++i) {
        if (!decompressAndWrite(g_embedded_specs[i], dest_dir))
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Sentinel: <cache_dir>/.complete
// ---------------------------------------------------------------------------

bool sentinelExists(const std::string& cache_dir) {
    std::string path = cache_dir + "/.complete";
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
#else
    struct stat st;
    return stat(path.c_str(), &st) == 0;
#endif
}

bool writeSentinel(const std::string& cache_dir) {
    std::string path = cache_dir + "/.complete";
    std::ofstream out(path);
    if (!out) return false;
    out << "ok\n";
    return out.good();
}

// ---------------------------------------------------------------------------
// Stale cache cleanup: remove sibling version dirs that aren't current
// ---------------------------------------------------------------------------

void cleanStaleCaches(const std::string& parent_dir, const std::string& current_key) {
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    std::string search = parent_dir + "\\*";
    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        if (fd.cFileName != current_key) {
            removeRecursive(parent_dir + "\\" + fd.cFileName);
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR* dir = opendir(parent_dir.c_str());
    if (!dir) return;
    struct dirent* entry;
    std::vector<std::string> stale;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        std::string child = parent_dir + "/" + entry->d_name;
        struct stat st;
        if (stat(child.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            if (entry->d_name != current_key)
                stale.push_back(child);
        }
    }
    closedir(dir);
    for (const auto& s : stale)
        removeRecursive(s);
#endif
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::string EmbeddedSpecManager::acquire() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_refcount == 0) {
        std::string cache_base = getUserCacheDir();
        std::string version_key = getVersionKey();
        std::string cache_dir = cache_base + "/" + version_key;

        if (sentinelExists(cache_dir)) {
            // Cache is valid — reuse it
            g_spec_dir = cache_dir;
        } else {
            // Extract specs to cache
            if (!makeDirsRecursive(cache_dir)) {
                fprintf(stderr, "ghidra_cpp: failed to create cache dir %s\n",
                        cache_dir.c_str());
            }
            if (!extractSpecs(cache_dir)) {
                fprintf(stderr, "ghidra_cpp: failed to extract specs to %s\n",
                        cache_dir.c_str());
            } else {
                writeSentinel(cache_dir);
            }
            g_spec_dir = cache_dir;

            // Clean up stale version dirs (best-effort, ignore errors)
            cleanStaleCaches(cache_base, version_key);
        }
    }

    ++g_refcount;
    return g_spec_dir;
}

void EmbeddedSpecManager::release() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_refcount <= 0) return;
    --g_refcount;
    // Cache persists on disk — no cleanup on release
}

} // namespace ghidra_embedded
