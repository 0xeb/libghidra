# cmake/GhidraSources.cmake
# Defines source file lists and targets for building Ghidra's decompiler from source.
# Source partitions mirror the Makefile in Ghidra/Features/Decompiler/src/decompile/cpp/

# ============================================================================
# Source file partitions (matching Makefile exactly)
# ============================================================================

# Core source files used in all projects
set(GHIDRA_CORE
    xml marshal space float address pcoderaw translate opcodes globalcontext
)

# Additional core files for any projects that decompile
set(GHIDRA_DECCORE
    bitfield capability architecture options graph cover block cast typeop database cpool
    comment stringmanage modelrules fspec action loadimage grammar varnode op type
    variable varmap jumptable emulate emulateutil flow userop expression multiprecision
    funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject
    heritage prefersplit rangeutil ruleaction subflow blockaction merge double
    transform constseq coreaction condexe override dynamic crc32 prettyprint
    printlanguage printc printjava memstate opbehavior paramid signature
)

# Files used for any project that uses the sleigh decoder
set(GHIDRA_SLEIGH
    sleigh pcodeparse pcodecompile sleighbase slghsymbol
    slghpatexpress slghpattern semantics context slaformat compression filemanage
)

# Additional files specific to the sleigh compiler
set(GHIDRA_SLACOMP
    slgh_compile slghparse slghscan
)

# EXTRA: additional modules for the command-line decompiler
# These are ALL_NAMES minus CORE, DECCORE, SLEIGH, GHIDRA, SLACOMP, and SPECIAL.
# Note: bfd_arch, loadimage_bfd, analyzesigs, codedata require GNU BFD (Linux only).
set(GHIDRA_EXTRA
    sleigh_arch inject_sleigh raw_arch xml_arch loadimage_xml
    ifacedecomp ifaceterm interface libdecomp
    callgraph rulecompile testfunction unify
)

# BFD-dependent files: only include on Linux when libbfd is actually discoverable.
# Previously we unconditionally added bfd_arch / loadimage_bfd / analyzesigs /
# codedata on Linux, compiled them into ghidra_libdecomp, and then linked the
# final nanobind module as a shared object WITHOUT linking libbfd. Because
# Linux shared libraries tolerate undefined symbols at link time, this
# produced wheels whose _libghidra.abi3.so has undefined bfd_init / bfd_openr
# / bfd_close / bfd_check_format / bfd_get_section_contents / bfd_printable_name
# references — import sometimes succeeds under RTLD_LAZY, but the moment
# ArchitectureCapability::findCapability tries the BFD path it blows up.
# Now we only include these files when both bfd.h and libbfd.a (or .so) are
# discoverable, and we actually link against libbfd.
set(LIBGHIDRA_HAS_BFD FALSE)
if(NOT MSVC AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_path(LIBGHIDRA_BFD_INCLUDE NAMES bfd.h)
    # Prefer libbfd.a — libbfd has an unstable ABI, static linking makes the
    # wheel self-contained and immune to binutils version skew on end-user
    # machines.
    find_library(LIBGHIDRA_BFD_LIB NAMES libbfd.a bfd)
    if(LIBGHIDRA_BFD_LIB AND LIBGHIDRA_BFD_INCLUDE)
        message(STATUS "libghidra: BFD-backed ELF loader enabled (lib=${LIBGHIDRA_BFD_LIB})")
        list(APPEND GHIDRA_EXTRA bfd_arch loadimage_bfd analyzesigs codedata)
        set(LIBGHIDRA_HAS_BFD TRUE)
    else()
        message(WARNING
            "libghidra: libbfd not found; the BFD-backed ELF auto-loader is disabled. "
            "Install binutils-devel (RHEL/Fedora/AlmaLinux) or binutils-dev (Debian/Ubuntu) "
            "to enable automatic loading of ELF binaries; otherwise callers must use "
            "raw_arch or loadimage_xml with an explicit language_id.")
    endif()
endif()

# Embedded zlib C sources
set(GHIDRA_ZLIB_SOURCES
    adler32 deflate inffast inflate inftrees trees zutil
)

# ============================================================================
# Build full path lists
# ============================================================================

set(LIBDECOMP_SOURCES "")
foreach(name ${GHIDRA_CORE} ${GHIDRA_DECCORE} ${GHIDRA_EXTRA} ${GHIDRA_SLEIGH})
    list(APPEND LIBDECOMP_SOURCES "${GHIDRA_DECOMP_SRC}/${name}.cc")
endforeach()

set(ZLIB_SOURCES "")
foreach(name ${GHIDRA_ZLIB_SOURCES})
    list(APPEND ZLIB_SOURCES "${GHIDRA_ZLIB_SRC}/${name}.c")
endforeach()

# ============================================================================
# Embedded zlib (OBJECT library, C)
# ============================================================================

add_library(ghidra_zlib OBJECT ${ZLIB_SOURCES})
target_include_directories(ghidra_zlib PUBLIC "${GHIDRA_ZLIB_SRC}")
set_target_properties(ghidra_zlib PROPERTIES LINKER_LANGUAGE C POSITION_INDEPENDENT_CODE ON)

target_compile_definitions(ghidra_zlib PRIVATE NO_GZIP)

if(MSVC)
    target_compile_options(ghidra_zlib PRIVATE /W3 /O2 /Oy /GL)
    target_compile_definitions(ghidra_zlib PRIVATE
        _CRT_SECURE_NO_DEPRECATE
        _CRT_NONSTDC_NO_DEPRECATE
        # Note: ZLIB_WINAPI intentionally omitted — it forces __stdcall on 32-bit
        # which breaks linking with the decompiler engine (expects cdecl).
    )
else()
    target_compile_options(ghidra_zlib PRIVATE -O2 -Wall)
endif()

# ============================================================================
# ghidra_libdecomp — full standalone decompiler OBJECT library
# Composition: CORE + DECCORE + EXTRA + SLEIGH (= LIBDECOMP_NAMES in Makefile)
# ============================================================================

add_library(ghidra_libdecomp OBJECT ${LIBDECOMP_SOURCES})
target_include_directories(ghidra_libdecomp PUBLIC "${GHIDRA_DECOMP_SRC}")
target_link_libraries(ghidra_libdecomp PUBLIC ghidra_zlib)
target_compile_definitions(ghidra_libdecomp PRIVATE LOCAL_ZLIB)
set_target_properties(ghidra_libdecomp PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(MSVC)
    target_compile_options(ghidra_libdecomp PRIVATE /EHsc /W3 /O2 /Oy /GL)
    target_compile_definitions(ghidra_libdecomp PRIVATE
        _SECURE_SCL=0
        _HAS_ITERATOR_DEBUGGING=0
        WINDOWS _WINDOWS WIN32 _WIN32
    )
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_compile_definitions(ghidra_libdecomp PRIVATE WIN64 _WIN64)
    endif()
    set_target_properties(ghidra_libdecomp PROPERTIES
        STATIC_LIBRARY_OPTIONS "/LTCG"
    )
else()
    target_compile_options(ghidra_libdecomp PRIVATE -O2 -Wall -Wno-sign-compare)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(ghidra_libdecomp PRIVATE LINUX _LINUX)
    endif()
endif()

# Link against libbfd (and friends) so the BFD-backed ELF loader compiled
# into ghidra_libdecomp has its bfd_* symbols resolved at build time instead
# of deferred to load/call time. Whole-archive propagation of libghidra_local
# then carries the BFD capability registration through to the wheel, and
# _libghidra.abi3.so ends up with no undefined bfd_* symbols — the wheel is
# genuinely self-contained on Linux with no libbfd on the host.
if(LIBGHIDRA_HAS_BFD)
    target_include_directories(ghidra_libdecomp PUBLIC "${LIBGHIDRA_BFD_INCLUDE}")
    target_link_libraries(ghidra_libdecomp PUBLIC "${LIBGHIDRA_BFD_LIB}")
    # libbfd.a may reference libiberty helpers (xmalloc, xstrdup, concat, ...);
    # pick it up if the distro ships it as a separate static archive.
    find_library(LIBGHIDRA_IBERTY_LIB NAMES libiberty.a iberty)
    if(LIBGHIDRA_IBERTY_LIB)
        target_link_libraries(ghidra_libdecomp PUBLIC "${LIBGHIDRA_IBERTY_LIB}")
    endif()
    # Newer binutils also splits out sframe/zstd; link if present, noop otherwise.
    find_library(LIBGHIDRA_SFRAME_LIB NAMES libsframe.a sframe)
    if(LIBGHIDRA_SFRAME_LIB)
        target_link_libraries(ghidra_libdecomp PUBLIC "${LIBGHIDRA_SFRAME_LIB}")
    endif()
    find_library(LIBGHIDRA_ZSTD_LIB NAMES libzstd.a zstd)
    if(LIBGHIDRA_ZSTD_LIB)
        target_link_libraries(ghidra_libdecomp PUBLIC "${LIBGHIDRA_ZSTD_LIB}")
    endif()
    # libbfd uses dlopen for format plugins; make sure libdl is linked.
    target_link_libraries(ghidra_libdecomp PUBLIC ${CMAKE_DL_LIBS})
endif()
