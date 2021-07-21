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

find_package(OpenSSL REQUIRED)

set (CMAKE_C_FLAGS "-O2 -DNDEBUG")
add_executable(DEternal_patchManifest ${SOURCES})

target_link_libraries(DEternal_patchManifest crypto)