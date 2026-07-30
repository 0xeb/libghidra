# Protobuf 29.3 predates CMake 4 and emits two deprecation warnings while
# configuring. Keep the pinned protobuf/gencode release train, but modernize
# only those build-system declarations in the fetched source tree.

if(NOT DEFINED LIBGHIDRA_PROTOBUF_SOURCE_DIR)
    message(FATAL_ERROR "LIBGHIDRA_PROTOBUF_SOURCE_DIR is required")
endif()

function(libghidra_replace_protobuf_cmake path old_text new_text)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "libghidra: protobuf CMake patch target is missing: ${path}")
    endif()

    file(READ "${path}" contents)
    string(FIND "${contents}" "${old_text}" old_position)
    if(NOT old_position EQUAL -1)
        string(REPLACE "${old_text}" "${new_text}" contents "${contents}")
        file(WRITE "${path}" "${contents}")
        return()
    endif()

    string(FIND "${contents}" "${new_text}" new_position)
    if(new_position EQUAL -1)
        message(FATAL_ERROR
            "libghidra: protobuf CMake input changed unexpectedly; refresh "
            "PatchProtobufCMake.cmake for ${path}")
    endif()
endfunction()

libghidra_replace_protobuf_cmake(
    "${LIBGHIDRA_PROTOBUF_SOURCE_DIR}/CMakeLists.txt"
    "cmake_policy(SET CMP0141 OLD)"
    "cmake_policy(SET CMP0141 NEW)"
)
libghidra_replace_protobuf_cmake(
    "${LIBGHIDRA_PROTOBUF_SOURCE_DIR}/third_party/utf8_range/CMakeLists.txt"
    "cmake_minimum_required (VERSION 3.5)"
    "cmake_minimum_required (VERSION 3.10...3.26)"
)
