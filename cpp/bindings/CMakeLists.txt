# cpp/bindings/CMakeLists.txt
# Builds the _libghidra Python extension module for libghidra local backend.
# Uses nanobind with stable ABI — one .pyd for all Python 3.12+.

# nanobind expects Python::Module (not Python3::Module), so use FindPython
find_package(Python 3.12 REQUIRED COMPONENTS Interpreter Development.Module Development.SABIModule)

FetchContent_Declare(
    nanobind
    GIT_REPOSITORY https://github.com/wjakob/nanobind.git
    GIT_TAG v2.12.0
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(nanobind)

nanobind_add_module(_libghidra
    STABLE_ABI
    NB_STATIC
    python_bindings.cpp
)
target_link_libraries(_libghidra PRIVATE libghidra::local_whole)

# ==========================================================================
# Output location — place .pyd where Python can find it during development
# ==========================================================================
set(LIBGHIDRA_PYTHON_PKG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../python/src/libghidra"
    CACHE PATH "Python package directory for _libghidra module output")

set_target_properties(_libghidra PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${LIBGHIDRA_PYTHON_PKG_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${LIBGHIDRA_PYTHON_PKG_DIR}"
)

# For multi-config generators (Visual Studio), flatten the output
foreach(config Release Debug RelWithDebInfo MinSizeRel)
    string(TOUPPER ${config} config_upper)
    set_target_properties(_libghidra PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY_${config_upper} "${LIBGHIDRA_PYTHON_PKG_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_${config_upper} "${LIBGHIDRA_PYTHON_PKG_DIR}"
    )
endforeach()
