# cmake/EmbedSpecs.cmake
# Runs embed_specs.py at configure time to generate embedded_specs.cpp/.h

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(GHIDRA_EMBED_PROCESSORS "ALL" CACHE STRING
    "Processors to embed (ALL or semicolon-separated list, e.g. x86;ARM;AARCH64)")

set(EMBED_SPECS_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/../embed_specs.py")
set(EMBEDDED_SPECS_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(EMBEDDED_LANGUAGES_PY
    "${CMAKE_CURRENT_LIST_DIR}/../../python/src/libghidra/known_languages.py")

# Convert semicolon-separated CMake list to comma-separated for Python
if(GHIDRA_EMBED_PROCESSORS STREQUAL "ALL")
    set(_PROC_ARG "")
else()
    string(REPLACE ";" "," _PROC_CSV "${GHIDRA_EMBED_PROCESSORS}")
    set(_PROC_ARG "--processors" "${_PROC_CSV}")
endif()

# Run at configure time
execute_process(
    COMMAND "${Python3_EXECUTABLE}" "${EMBED_SPECS_SCRIPT}"
            "${GHIDRA_SOURCE_DIR}" "${EMBEDDED_SPECS_DIR}"
            --python-output "${EMBEDDED_LANGUAGES_PY}"
            ${_PROC_ARG}
    RESULT_VARIABLE _EMBED_RESULT
    OUTPUT_VARIABLE _EMBED_OUTPUT
    ERROR_VARIABLE  _EMBED_ERROR
)

if(NOT _EMBED_RESULT EQUAL 0)
    message(FATAL_ERROR
        "embed_specs.py failed (exit ${_EMBED_RESULT}):\n${_EMBED_ERROR}")
endif()

message(STATUS "${_EMBED_OUTPUT}")

set(EMBEDDED_SPECS_SOURCES
    "${EMBEDDED_SPECS_DIR}/embedded_specs.cpp"
    "${EMBEDDED_SPECS_DIR}/embedded_specs.h"
)
