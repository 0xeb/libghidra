# cpp/CMakeLists.txt
# Defines two targets from a single directory:
#   libghidra_client — IClient interface + models + StatusOr + HTTP backend + protobuf stubs
#   libghidra_local  — Adds local/offline backend (decompiler engine, project reader)

cmake_minimum_required(VERSION 3.24)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION" LIBGHIDRA_VERSION)
string(STRIP "${LIBGHIDRA_VERSION}" LIBGHIDRA_VERSION)
project(libghidra_cpp VERSION ${LIBGHIDRA_VERSION} LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ============================================================================
# Options
# ============================================================================

option(LIBGHIDRA_WITH_LOCAL "Build the local (offline) backend" OFF)
option(LIBGHIDRA_BUILD_EXAMPLES "Build examples" OFF)
option(LIBGHIDRA_BUILD_PYTHON "Build Python native extension (nanobind, requires LOCAL)" OFF)

# When building the Python nanobind extension the static libraries
# (libghidra_client, libghidra_local) end up inside a shared module, so every
# object they contain must be position-independent. On Linux ELF the linker
# rejects R_X86_64_32S relocations against vtables/RTTI otherwise:
#
#   relocation R_X86_64_32S against symbol '_ZTVN...' can not be used when
#   making a shared object; recompile with -fPIC
#
# Enable PIC globally in this configuration; it's a no-op on macOS/Windows.
if(LIBGHIDRA_BUILD_PYTHON)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# GHIDRA_SOURCE_DIR: path to the Ghidra source tree.
# Required when LIBGHIDRA_WITH_LOCAL is ON.
if(LIBGHIDRA_WITH_LOCAL AND NOT DEFINED GHIDRA_SOURCE_DIR)
    message(FATAL_ERROR
        "GHIDRA_SOURCE_DIR must be set when LIBGHIDRA_WITH_LOCAL is ON.\n"
        "Point it at a Ghidra source tree (e.g. -DGHIDRA_SOURCE_DIR=/path/to/ghidra).")
endif()

# Normalise to forward slashes so Windows paths like "D:\a\..." don't trigger
# CMake's invalid-character-escape parse errors when concatenated into source
# lists (e.g. add_library("${GHIDRA_ZLIB_SRC}/adler32.c")).
if(DEFINED GHIDRA_SOURCE_DIR)
    file(TO_CMAKE_PATH "${GHIDRA_SOURCE_DIR}" GHIDRA_SOURCE_DIR)
endif()

# ============================================================================
# Dependencies: protobuf + cpp-httplib (always needed for libghidra_client)
# ============================================================================

include(FetchContent)

set(LIBGHIDRA_HTTPLIB_INCLUDE_DIR "")
if(NOT TARGET httplib::httplib)
    FetchContent_Declare(
        cpp_httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.16.3
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(cpp_httplib)
    set(LIBGHIDRA_HTTPLIB_INCLUDE_DIR "${cpp_httplib_SOURCE_DIR}")
endif()

set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_CONFORMANCE OFF CACHE BOOL "" FORCE)
set(protobuf_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_PROTOBUF_BINARIES ON CACHE BOOL "" FORCE)
set(protobuf_BUILD_LIBUPB OFF CACHE BOOL "" FORCE)
set(protobuf_DISABLE_RTTI OFF CACHE BOOL "" FORCE)
if(MSVC)
    # Protobuf exposes a single CRT mode toggle, so follow the top-level MSVC
    # runtime selection.  When CMAKE_MSVC_RUNTIME_LIBRARY is not set, MSVC
    # defaults to the dynamic CRT (/MD), so protobuf must match.
    if(DEFINED CMAKE_MSVC_RUNTIME_LIBRARY AND NOT CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
        set(protobuf_MSVC_STATIC_RUNTIME ON CACHE BOOL "" FORCE)
    else()
        set(protobuf_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
    endif()
endif()
FetchContent_Declare(
    protobuf
    GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
    GIT_TAG v29.3
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(protobuf)

# Protobuf v29.3 ships abseil-cpp 20240722.0, whose AbseilConfigureCopts.cmake
# misdetects the arch on macOS Apple Silicon and pins -msse4.1/-maes onto the
# random_internal_randen_hwaes* targets, which clang rejects when targeting
# arm64. Strip those x86-only flags so the targets build (the sources have
# preprocessor guards that cleanly fall back without HW AES).
if(APPLE)
    foreach(_libghidra_absl_target
        random_internal_randen_hwaes
        random_internal_randen_hwaes_impl
    )
        if(TARGET ${_libghidra_absl_target})
            get_target_property(_libghidra_hwaes_opts ${_libghidra_absl_target} COMPILE_OPTIONS)
            if(_libghidra_hwaes_opts)
                list(REMOVE_ITEM _libghidra_hwaes_opts "-msse4.1" "-maes" "-mssse3" "-msse4.2")
                set_property(TARGET ${_libghidra_absl_target} PROPERTY COMPILE_OPTIONS ${_libghidra_hwaes_opts})
            endif()
        endif()
    endforeach()
endif()

# ============================================================================
# Auto-regenerate C++ protobuf stubs when .proto files change
# ============================================================================

if(TARGET protoc)
    set(LIBGHIDRA_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../proto/libghidra")
    set(LIBGHIDRA_PROTO_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../proto")
    set(LIBGHIDRA_GEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/generated/libghidra")

    file(GLOB LIBGHIDRA_PROTO_FILES "${LIBGHIDRA_PROTO_DIR}/*.proto")

    set(LIBGHIDRA_GEN_SRCS "")
    set(LIBGHIDRA_GEN_HDRS "")
    foreach(proto_file ${LIBGHIDRA_PROTO_FILES})
        get_filename_component(proto_name "${proto_file}" NAME_WE)
        list(APPEND LIBGHIDRA_GEN_SRCS "${LIBGHIDRA_GEN_DIR}/${proto_name}.pb.cc")
        list(APPEND LIBGHIDRA_GEN_HDRS "${LIBGHIDRA_GEN_DIR}/${proto_name}.pb.h")
    endforeach()

    add_custom_command(
        OUTPUT ${LIBGHIDRA_GEN_SRCS} ${LIBGHIDRA_GEN_HDRS}
        COMMAND $<TARGET_FILE:protoc>
            --proto_path=${LIBGHIDRA_PROTO_INCLUDE}
            --proto_path=${protobuf_SOURCE_DIR}/src
            --cpp_out=${CMAKE_CURRENT_SOURCE_DIR}/generated
            ${LIBGHIDRA_PROTO_FILES}
        DEPENDS ${LIBGHIDRA_PROTO_FILES} protoc
        COMMENT "Regenerating C++ protobuf stubs from .proto files"
        VERBATIM
    )
endif()

# ============================================================================
# Target: libghidra_client (IClient + HTTP backend + protobuf stubs)
# ============================================================================

add_library(libghidra_client
    src/http_client.cpp
    src/headless.cpp
    generated/libghidra/common.pb.cc
    generated/libghidra/decompiler.pb.cc
    generated/libghidra/functions.pb.cc
    generated/libghidra/health.pb.cc
    generated/libghidra/listing.pb.cc
    generated/libghidra/memory.pb.cc
    generated/libghidra/session.pb.cc
    generated/libghidra/symbols.pb.cc
    generated/libghidra/types.pb.cc
    generated/libghidra/xrefs.pb.cc
    generated/libghidra/rpc.pb.cc
)
add_library(libghidra::client ALIAS libghidra_client)
set_target_properties(libghidra_client PROPERTIES EXPORT_NAME client)

target_compile_features(libghidra_client PUBLIC cxx_std_20)
target_include_directories(libghidra_client PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/generated>
    $<BUILD_INTERFACE:${protobuf_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${protobuf_BINARY_DIR}/src>
    $<BUILD_INTERFACE:${protobuf_SOURCE_DIR}/third_party/abseil-cpp>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(libghidra_client PRIVATE
    $<$<BOOL:${LIBGHIDRA_HTTPLIB_INCLUDE_DIR}>:${LIBGHIDRA_HTTPLIB_INCLUDE_DIR}>
)

set(LIBGHIDRA_PROTOBUF_TARGET "")
if(TARGET protobuf::libprotobuf)
    set(LIBGHIDRA_PROTOBUF_TARGET protobuf::libprotobuf)
elseif(TARGET protobuf::protobuf)
    set(LIBGHIDRA_PROTOBUF_TARGET protobuf::protobuf)
elseif(TARGET libprotobuf)
    set(LIBGHIDRA_PROTOBUF_TARGET libprotobuf)
else()
    message(FATAL_ERROR "libghidra: missing protobuf target (expected protobuf::libprotobuf or libprotobuf)")
endif()

set(LIBGHIDRA_PROTOBUF_LITE_TARGET "")
if(TARGET protobuf::libprotobuf-lite)
    set(LIBGHIDRA_PROTOBUF_LITE_TARGET protobuf::libprotobuf-lite)
elseif(TARGET libprotobuf-lite)
    set(LIBGHIDRA_PROTOBUF_LITE_TARGET libprotobuf-lite)
endif()

target_link_libraries(libghidra_client PUBLIC ${LIBGHIDRA_PROTOBUF_TARGET})
if(TARGET httplib::httplib)
    target_link_libraries(libghidra_client PRIVATE httplib::httplib)
elseif(NOT LIBGHIDRA_HTTPLIB_INCLUDE_DIR)
    message(FATAL_ERROR "libghidra: missing cpp-httplib include source/target")
endif()

if(LIBGHIDRA_PROTOBUF_LITE_TARGET
   AND NOT LIBGHIDRA_PROTOBUF_LITE_TARGET STREQUAL LIBGHIDRA_PROTOBUF_TARGET)
    target_link_libraries(libghidra_client PUBLIC ${LIBGHIDRA_PROTOBUF_LITE_TARGET})
endif()

# ============================================================================
# Target: libghidra_local (offline backend via standalone Ghidra decompiler)
# ============================================================================

if(LIBGHIDRA_WITH_LOCAL)
    # -- Decompiler engine setup (was in decompiler/CMakeLists.txt) --
    set(GHIDRA_DECOMP_SRC "${GHIDRA_SOURCE_DIR}/Ghidra/Features/Decompiler/src/decompile/cpp")
    set(GHIDRA_ZLIB_SRC "${GHIDRA_SOURCE_DIR}/Ghidra/Features/Decompiler/src/decompile/zlib")

    if(NOT EXISTS "${GHIDRA_DECOMP_SRC}/libdecomp.hh")
        message(FATAL_ERROR
            "Cannot find Ghidra decompiler sources at ${GHIDRA_DECOMP_SRC}\n"
            "Make sure GHIDRA_SOURCE_DIR points to an initialized Ghidra source tree.")
    endif()

    include(cmake/GhidraSources.cmake)
    include(cmake/EmbedSpecs.cmake)

    # -- ghidra_cpp engine (was in decompiler/src/CMakeLists.txt) --
    set(GHIDRA_ENGINE_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/force_capabilities.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidra_cpp_init.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidra_decompiler.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidradb/buffer_file.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidradb/db_record.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidradb/btree.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidradb/address_map.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidradb/ghidra_project.cpp
        ${EMBEDDED_SPECS_SOURCES}
    )

    add_library(libghidra_local STATIC
        src/local_client.cpp
        src/local_arch_adapter.cpp
        src/decompiler_pool.cpp
        ${GHIDRA_ENGINE_SOURCES}
        $<TARGET_OBJECTS:ghidra_libdecomp>
        $<TARGET_OBJECTS:ghidra_zlib>
    )
    add_library(libghidra::local ALIAS libghidra_local)
    set_target_properties(libghidra_local PROPERTIES EXPORT_NAME local)

    target_include_directories(libghidra_local PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )

    # Implementation headers
    target_include_directories(libghidra_local PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine
        ${CMAKE_CURRENT_SOURCE_DIR}/src/engine/ghidradb
        ${GHIDRA_DECOMP_SRC}
        ${GHIDRA_ZLIB_SRC}
        ${EMBEDDED_SPECS_DIR}
    )

    # PUBLIC link to libghidra_client for IClient, models, status
    target_link_libraries(libghidra_local PUBLIC libghidra_client)

    # ghidra_libdecomp is an OBJECT library embedded via $<TARGET_OBJECTS:...>
    # above. That embeds the .o files cleanly, but it does NOT propagate
    # ghidra_libdecomp's INTERFACE link dependencies (libbfd, libiberty, libdl)
    # to libghidra_local. Without re-stating them here, _libghidra.abi3.so
    # ends up with undefined bfd_init / bfd_openr / bfd_close /
    # bfd_check_format / bfd_get_section_contents / bfd_printable_name
    # references that the dynamic loader can't resolve at runtime.
    if(LIBGHIDRA_HAS_BFD)
        target_link_libraries(libghidra_local PUBLIC "${LIBGHIDRA_BFD_LIB}")
        if(LIBGHIDRA_IBERTY_LIB)
            target_link_libraries(libghidra_local PUBLIC "${LIBGHIDRA_IBERTY_LIB}")
        endif()
        if(LIBGHIDRA_SFRAME_LIB)
            target_link_libraries(libghidra_local PUBLIC "${LIBGHIDRA_SFRAME_LIB}")
        endif()
        if(LIBGHIDRA_ZSTD_LIB)
            target_link_libraries(libghidra_local PUBLIC "${LIBGHIDRA_ZSTD_LIB}")
        endif()
        target_link_libraries(libghidra_local PUBLIC ${CMAKE_DL_LIBS})
    endif()

    # Whole-archive wrapper. libghidra_local relies on static-initialiser
    # registration of Ghidra's ArchitectureCapability subclasses, which the
    # linker strips under default linkage because nothing references those
    # translation units directly. Consumers that need the registrations to
    # survive (the Python nanobind extension, the local-backend examples)
    # must link against this wrapper instead of libghidra_local.
    #
    # Using the CMake 3.24 generator expression keeps the archive referenced
    # exactly once in the final link — the previous pattern of emitting
    # "-Wl,--whole-archive $<TARGET_FILE:libghidra_local> -Wl,--no-whole-archive"
    # via INTERFACE duplicated every object file on Linux because CMake's
    # target resolution already linked libghidra_local normally.
    add_library(libghidra_local_whole INTERFACE)
    add_library(libghidra::local_whole ALIAS libghidra_local_whole)
    target_link_libraries(libghidra_local_whole INTERFACE
        $<LINK_LIBRARY:WHOLE_ARCHIVE,libghidra_local>
    )

    # Threading support for DecompilerPool
    find_package(Threads REQUIRED)
    target_link_libraries(libghidra_local PUBLIC Threads::Threads)

    target_compile_features(libghidra_local PUBLIC cxx_std_20)
    target_compile_definitions(libghidra_local PRIVATE LOCAL_ZLIB)

    if(MSVC)
        target_compile_options(libghidra_local PRIVATE /EHsc /W3 /O2)
        target_compile_definitions(libghidra_local PRIVATE
            _SECURE_SCL=0
            _HAS_ITERATOR_DEBUGGING=0
            WINDOWS _WINDOWS WIN32 _WIN32
        )
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_compile_definitions(libghidra_local PRIVATE WIN64 _WIN64)
        endif()
    else()
        target_compile_options(libghidra_local PRIVATE -O2 -Wall -Wno-sign-compare)
    endif()

    # On Windows, link ws2_32 for networking (used by some Ghidra code paths)
    if(WIN32)
        target_link_libraries(libghidra_local PUBLIC ws2_32)
    endif()
endif()

# ============================================================================
# Installation / package export
# ============================================================================

set(LIBGHIDRA_PACKAGE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/libghidra")

install(TARGETS libghidra_client
    EXPORT libghidraTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(TARGET libghidra_local)
    install(TARGETS libghidra_local
        EXPORT libghidraTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/libghidra"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/generated/libghidra"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libghidra
    FILES_MATCHING PATTERN "*.h"
)

install(EXPORT libghidraTargets
    FILE libghidraTargets.cmake
    NAMESPACE libghidra::
    DESTINATION ${LIBGHIDRA_PACKAGE_INSTALL_DIR}
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/libghidraConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/libghidraConfig.cmake"
    INSTALL_DESTINATION ${LIBGHIDRA_PACKAGE_INSTALL_DIR}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/libghidraConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/libghidraConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libghidraConfigVersion.cmake"
    DESTINATION ${LIBGHIDRA_PACKAGE_INSTALL_DIR}
)

# ============================================================================
# Examples (optional)
# ============================================================================

if(LIBGHIDRA_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ============================================================================
# Python bindings (optional, requires local backend)
# ============================================================================

if(LIBGHIDRA_BUILD_PYTHON)
    if(NOT LIBGHIDRA_WITH_LOCAL)
        message(FATAL_ERROR
            "LIBGHIDRA_BUILD_PYTHON requires LIBGHIDRA_WITH_LOCAL=ON.")
    endif()
    add_subdirectory(bindings)
endif()
