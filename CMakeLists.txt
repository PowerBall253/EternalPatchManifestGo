cmake_minimum_required(VERSION 3.12)
project(EternalPatchManifest)

set(CMAKE_C_STANDARD 99)

file(GLOB SOURCES
        ./main.c
        ./crypto.c
        ./crypto.h
        ./cJSON/cJSON.c
        ./cJSON/cJSON.h
        )

if(DEFINED ENV{ETERNALPATCHMANIFESTLINUX_STATIC})
        set (CMAKE_C_FLAGS "-O2 -static -s")
        set(OPENSSL_USE_STATIC_LIBS TRUE)
else()
        set (CMAKE_C_FLAGS "-O2 -s")
endif()

find_package(OpenSSL "3.0" REQUIRED)

add_executable(DEternal_patchManifest ${SOURCES})
target_link_libraries(DEternal_patchManifest OpenSSL::Crypto)
