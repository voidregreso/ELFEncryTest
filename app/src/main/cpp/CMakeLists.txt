cmake_minimum_required(VERSION 3.22.1)

project("elfencrytest")

# Set OpenSSL include and library path
set(OPENSSL_ROOT_DIR ${CMAKE_SOURCE_DIR}/openssl-1.1.1k-clang)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)

include_directories(${OPENSSL_INCLUDE_DIR})

# Set linkage path according to the CPU architecture
if(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(OPENSSL_ARCH_LIB_DIR ${OPENSSL_ROOT_DIR}/armeabi-v7a/lib)
elseif(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(OPENSSL_ARCH_LIB_DIR ${OPENSSL_ROOT_DIR}/arm64-v8a/lib)
elseif(${ANDROID_ABI} STREQUAL "x86")
    set(OPENSSL_ARCH_LIB_DIR ${OPENSSL_ROOT_DIR}/x86/lib)
elseif(${ANDROID_ABI} STREQUAL "x86_64")
    set(OPENSSL_ARCH_LIB_DIR ${OPENSSL_ROOT_DIR}/x86_64/lib)
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_ARCH_LIB_DIR})

add_library(cryutil SHARED
        utils.c)

target_compile_options(cryutil PRIVATE -fexceptions -Os -ffunction-sections -fdata-sections -fvisibility=hidden -w -Wl,--gc-sections)

target_link_libraries(cryutil
        android log
        # For OpenSSL
        ssl crypto
)

add_library(${CMAKE_PROJECT_NAME} SHARED main.c dec.c)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE -fexceptions -Os -ffunction-sections -fdata-sections -fvisibility=hidden -w -Wl,--gc-sections)

target_link_options(elfencrytest PRIVATE
        -Wl,--section-start=.preload=0x10000
)

target_link_libraries(${CMAKE_PROJECT_NAME}
        android log
        cryutil
)