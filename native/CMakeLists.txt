cmake_minimum_required(VERSION 3.22)
project(arm32_bridge LANGUAGES C CXX)

# Rename the target to the .so name the game's Java side loads with
# System.loadLibrary(). Nothing else in the build depends on the name.
set(BRIDGE_TARGET main CACHE STRING "Host library name loaded by Java")
set(GAME_CONFIG_DIR "" CACHE PATH "Directory containing game_port_config.h")
if(NOT GAME_CONFIG_DIR OR NOT EXISTS "${GAME_CONFIG_DIR}/game_port_config.h")
    message(FATAL_ERROR "GAME_CONFIG_DIR must contain game_port_config.h")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

set(DYNARMIC_REVISION "e77b1ba0b7da7cbe93021b01a663acfe7c4dd516")
if(NOT FETCHCONTENT_SOURCE_DIR_DYNARMIC OR
   NOT IS_ABSOLUTE "${FETCHCONTENT_SOURCE_DIR_DYNARMIC}" OR
   NOT EXISTS "${FETCHCONTENT_SOURCE_DIR_DYNARMIC}")
    message(FATAL_ERROR "FETCHCONTENT_SOURCE_DIR_DYNARMIC must be an existing absolute local Dynarmic checkout")
endif()
if(NOT FETCHCONTENT_FULLY_DISCONNECTED OR NOT FETCHCONTENT_UPDATES_DISCONNECTED)
    message(FATAL_ERROR "FETCHCONTENT_FULLY_DISCONNECTED and FETCHCONTENT_UPDATES_DISCONNECTED must both be ON")
endif()
if(NOT CMAKE_ANDROID_NDK OR NOT IS_DIRECTORY "${CMAKE_ANDROID_NDK}")
    message(FATAL_ERROR "CMAKE_ANDROID_NDK must select the installed Android NDK")
endif()

# Keep project-specific Dynarmic changes in this source tree.  The caller's
# pinned checkout stays pristine; every configure copies it into the build tree
# and applies the checked-in patch there.
find_package(Git REQUIRED)
get_filename_component(DYNARMIC_UPSTREAM_SOURCE_DIR
                       "${FETCHCONTENT_SOURCE_DIR_DYNARMIC}" REALPATH)
execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${DYNARMIC_UPSTREAM_SOURCE_DIR}" rev-parse HEAD
    RESULT_VARIABLE DYNARMIC_REVISION_RESULT
    OUTPUT_VARIABLE DYNARMIC_ACTUAL_REVISION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT DYNARMIC_REVISION_RESULT EQUAL 0 OR
   NOT DYNARMIC_ACTUAL_REVISION STREQUAL DYNARMIC_REVISION)
    message(FATAL_ERROR
        "Dynarmic checkout must be at ${DYNARMIC_REVISION}; got '${DYNARMIC_ACTUAL_REVISION}'")
endif()
execute_process(
    COMMAND "${GIT_EXECUTABLE}" -C "${DYNARMIC_UPSTREAM_SOURCE_DIR}"
            status --porcelain --untracked-files=all --ignore-submodules=none
    RESULT_VARIABLE DYNARMIC_STATUS_RESULT
    OUTPUT_VARIABLE DYNARMIC_STATUS
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT DYNARMIC_STATUS_RESULT EQUAL 0 OR DYNARMIC_STATUS)
    message(FATAL_ERROR "Dynarmic checkout must be clean; status: '${DYNARMIC_STATUS}'")
endif()

set(DYNARMIC_PATCH
    "${CMAKE_CURRENT_SOURCE_DIR}/patches/dynarmic/0001-arm64-a32-limit-prelude-icache-invalidation.patch")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${DYNARMIC_PATCH}")
file(SHA256 "${DYNARMIC_PATCH}" DYNARMIC_PATCH_SHA256)
string(SUBSTRING "${DYNARMIC_PATCH_SHA256}" 0 12 DYNARMIC_PATCH_ID)
set(DYNARMIC_PATCHED_SOURCE_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/patched_dependencies/dynarmic-${DYNARMIC_REVISION}-${DYNARMIC_PATCH_ID}")
set(DYNARMIC_A32_ADDRESS_SPACE
    "src/dynarmic/backend/arm64/a32_address_space.cpp")
set(DYNARMIC_PATCHED_A32_ADDRESS_SPACE
    "${DYNARMIC_PATCHED_SOURCE_DIR}/${DYNARMIC_A32_ADDRESS_SPACE}")
set(DYNARMIC_PATCH_READY OFF)
if(EXISTS "${DYNARMIC_PATCHED_A32_ADDRESS_SPACE}")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" apply --reverse --check --no-index "${DYNARMIC_PATCH}"
        WORKING_DIRECTORY "${DYNARMIC_PATCHED_SOURCE_DIR}"
        RESULT_VARIABLE DYNARMIC_REVERSE_PATCH_CHECK_RESULT
        ERROR_QUIET
    )
    if(DYNARMIC_REVERSE_PATCH_CHECK_RESULT EQUAL 0)
        set(DYNARMIC_PATCH_READY ON)
    endif()
endif()

if(NOT DYNARMIC_PATCH_READY)
    # This path is wholly derived from CMAKE_CURRENT_BINARY_DIR, the pinned
    # revision, and the patch hash.  Recreate only this generated dependency.
    file(REMOVE_RECURSE "${DYNARMIC_PATCHED_SOURCE_DIR}")
    file(COPY "${DYNARMIC_UPSTREAM_SOURCE_DIR}/"
         DESTINATION "${DYNARMIC_PATCHED_SOURCE_DIR}"
         PATTERN ".git" EXCLUDE)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" apply --check --no-index "${DYNARMIC_PATCH}"
        WORKING_DIRECTORY "${DYNARMIC_PATCHED_SOURCE_DIR}"
        RESULT_VARIABLE DYNARMIC_PATCH_CHECK_RESULT
        ERROR_VARIABLE DYNARMIC_PATCH_CHECK_ERROR
    )
    if(NOT DYNARMIC_PATCH_CHECK_RESULT EQUAL 0)
        message(FATAL_ERROR "Dynarmic patch does not apply cleanly: ${DYNARMIC_PATCH_CHECK_ERROR}")
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" apply --no-index "${DYNARMIC_PATCH}"
        WORKING_DIRECTORY "${DYNARMIC_PATCHED_SOURCE_DIR}"
        RESULT_VARIABLE DYNARMIC_PATCH_RESULT
        ERROR_VARIABLE DYNARMIC_PATCH_ERROR
    )
    if(NOT DYNARMIC_PATCH_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to apply Dynarmic patch: ${DYNARMIC_PATCH_ERROR}")
    endif()
endif()

set(FETCHCONTENT_SOURCE_DIR_DYNARMIC "${DYNARMIC_PATCHED_SOURCE_DIR}")
message(STATUS "Using pinned Dynarmic: ${DYNARMIC_UPSTREAM_SOURCE_DIR}")
message(STATUS "Using patched Dynarmic copy: ${FETCHCONTENT_SOURCE_DIR_DYNARMIC}")
message(STATUS "Using Android NDK: ${CMAKE_ANDROID_NDK}")

# Size: applied before FetchContent so dynarmic/fmt/mcl inherit them. Only
# JNI_OnLoad has to be exported (everything else is registered at runtime), so
# hiding the rest drops the dynsym table and most of .rela.
add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden
                    -ffunction-sections -fdata-sections)
add_link_options(-Wl,--gc-sections -Wl,--icf=all -Wl,--exclude-libs,ALL)

# Boost Headers
set(BOOST_ROOT "" CACHE PATH "External Boost 1.83 header root")
if(NOT EXISTS "${BOOST_ROOT}/boost/version.hpp")
    message(FATAL_ERROR "BOOST_ROOT must contain boost/version.hpp (Boost 1.83)")
endif()
set(BOOST_INCLUDEDIR "${BOOST_ROOT}")
set(Boost_INCLUDE_DIR "${BOOST_ROOT}")
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_FOUND TRUE)
include_directories("${BOOST_ROOT}")

# Configure Dynarmic.
# NOTE: the real option is DYNARMIC_FRONTENDS (a list), not DYNARMIC_ENABLE_A32/A64 --
# the old names were silently ignored, so A64 was being built too.
set(DYNARMIC_FRONTENDS "A32" CACHE STRING "" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "" FORCE)  # cross-compiling: never pick up host libs

option(ARM32_BRIDGE_ENABLE_JIT_PERF_MAP
       "Write ARM64 Dynarmic JIT blocks to a standard perf-<pid>.map file"
       OFF)
set(ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY "/data/local/tmp" CACHE STRING
    "Directory for the diagnostic Dynarmic perf-<pid>.map file")
option(ARM32_BRIDGE_ENABLE_DYNARMIC_VALIDATION
       "Run expensive Dynarmic IR and register-allocation validation"
       OFF)
option(ARM32_BRIDGE_ENABLE_LOGGING
       "Enable internal bridge logging via __android_log_print"
       OFF)

FetchContent_Declare(
    dynarmic
    GIT_REPOSITORY https://github.com/azahar-emu/dynarmic.git
    GIT_TAG        ${DYNARMIC_REVISION}
)
FetchContent_MakeAvailable(dynarmic)

if(ARM32_BRIDGE_ENABLE_DYNARMIC_VALIDATION)
    target_compile_definitions(dynarmic PRIVATE
        DYNARMIC_ENABLE_JIT_VALIDATION=1)
    message(WARNING
        "Dynarmic JIT validation enabled; this is intended for diagnostic builds only")
endif()

if(ARM32_BRIDGE_ENABLE_JIT_PERF_MAP)
    if(NOT ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY OR
       ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY MATCHES "[\";]")
        message(FATAL_ERROR
            "ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY must be non-empty and contain no quote or semicolon")
    endif()
    target_compile_definitions(dynarmic PRIVATE
        DYNARMIC_ENABLE_ARM64_PERF_MAP=1
        "DYNARMIC_ARM64_PERF_MAP_DIRECTORY=\"${ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY}\"")
    message(WARNING
        "Dynarmic JIT perf-map diagnostics enabled: ${ARM32_BRIDGE_JIT_PERF_MAP_DIRECTORY}/perf-<pid>.map")
endif()

set(BRIDGE_SOURCES
    src/elf_loader.cpp
    src/dynarmic_host.cpp
    src/thunk_manager.cpp
    src/thunks_gl.cpp
    src/thunks_gl_gles2_core.cpp
    src/thunks_android.cpp
    src/thunks_libc.cpp
    src/thunks_opensles.cpp   # drop this line if the game is not on FMOD Ex
    src/telltale_addcallback_fastpath.cpp
    src/telltale_propertyset_fastpath.cpp
    src/presentation_pacer.cpp
    src/telltale_fps.cpp
    src/jni_fake_env.cpp
    src/jni_bridge.cpp
    src/cache_bootstrap.cpp
)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/telltale_fps.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/fps_image_pin_check.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/../app/assets/guestlib/armeabi-v7a/libGameEngine.so")
execute_process(
    COMMAND "${Python3_EXECUTABLE}" -X utf8 -B "${CMAKE_CURRENT_SOURCE_DIR}/tests/fps_image_pin_check.py"
    RESULT_VARIABLE FPS_IMAGE_PIN_RESULT
)
if(NOT FPS_IMAGE_PIN_RESULT EQUAL 0)
    message(FATAL_ERROR "TFTB native FPS fingerprint does not match the original engine")
endif()
set(GUEST_QSORT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/guest_qsort_image.h")
add_custom_command(
    OUTPUT "${GUEST_QSORT_HEADER}"
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/build_guest_qsort.py"
            --ndk "${CMAKE_ANDROID_NDK}"
            --source "${CMAKE_CURRENT_SOURCE_DIR}/src/guest_qsort.c"
            --output "${GUEST_QSORT_HEADER}"
            --work-dir "${CMAKE_CURRENT_BINARY_DIR}/guest_qsort"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/build_guest_qsort.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/guest_qsort.c"
    VERBATIM
)
add_custom_target(guest_qsort_image DEPENDS "${GUEST_QSORT_HEADER}")

add_library(${BRIDGE_TARGET} SHARED ${BRIDGE_SOURCES})
add_dependencies(${BRIDGE_TARGET} guest_qsort_image)

target_include_directories(${BRIDGE_TARGET} PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${GAME_CONFIG_DIR}
    ${dynarmic_SOURCE_DIR}/include
    ${BOOST_ROOT}
)

target_link_libraries(${BRIDGE_TARGET} PRIVATE
    dynarmic
    GLESv2
    GLESv1_CM
    EGL
    OpenSLES
    log
    android
    m
    z
)

target_compile_definitions(${BRIDGE_TARGET} PRIVATE
    ANDROID
    __ANDROID__
    ARM32_BRIDGE_ENABLE_LOGGING=$<BOOL:${ARM32_BRIDGE_ENABLE_LOGGING}>
)

# Android 15+ devices boot with 16 KB pages; a 4 KB-aligned LOAD segment trips
# the "app isn't 16 KB compatible" loader warning.
target_link_options(${BRIDGE_TARGET} PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
    "-Wl,-z,relro"
    "-Wl,-z,now"
)

add_executable(guest_qsort_test EXCLUDE_FROM_ALL
    tests/guest_qsort_test.cpp ${BRIDGE_SOURCES})
add_dependencies(guest_qsort_test guest_qsort_image)
target_include_directories(guest_qsort_test PRIVATE
    src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${GAME_CONFIG_DIR}
    ${dynarmic_SOURCE_DIR}/include
    ${BOOST_ROOT}
)
target_link_libraries(guest_qsort_test PRIVATE
    dynarmic
    GLESv2
    GLESv1_CM
    EGL
    OpenSLES
    log
    android
    m
    z
)
target_compile_definitions(guest_qsort_test PRIVATE ANDROID __ANDROID__ BRIDGE_OPENSL_TEST ARM32_BRIDGE_ENABLE_LOGGING=$<BOOL:${ARM32_BRIDGE_ENABLE_LOGGING}>)
target_compile_options(guest_qsort_test PRIVATE -UNDEBUG)
target_link_options(guest_qsort_test PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
    "-Wl,-z,relro"
    "-Wl,-z,now"
)

add_executable(elf_loader_test EXCLUDE_FROM_ALL
    tests/elf_loader_test.cpp src/elf_loader.cpp)
target_include_directories(elf_loader_test PRIVATE src)
target_compile_definitions(elf_loader_test PRIVATE ANDROID __ANDROID__ ARM32_BRIDGE_ENABLE_LOGGING=$<BOOL:${ARM32_BRIDGE_ENABLE_LOGGING}>)
target_compile_options(elf_loader_test PRIVATE -UNDEBUG -Wall -Wextra -Werror)
target_link_libraries(elf_loader_test PRIVATE log)
