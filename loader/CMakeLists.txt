cmake_minimum_required(VERSION 3.24)
project(gta6rt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(gta6rt
    src/main.cpp
    src/pe_image.cpp
    src/shims.cpp
)

if (MSVC)
    target_compile_options(gta6rt PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(gta6rt PRIVATE _CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

# The loader maps the game at its preferred base 0x140000000, so move the
# loader itself out of the way and disable ASLR.
if (MSVC)
    target_link_options(gta6rt PRIVATE /DYNAMICBASE:NO /BASE:0x10000000)
endif()
