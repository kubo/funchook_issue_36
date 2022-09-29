cmake_minimum_required(VERSION 3.6)

set(FUNCHOOK_BUILD_STATIC ON CACHE BOOL "build static library")
set(FUNCHOOK_BUILD_SHARED OFF  CACHE BOOL "build shared library")
set(FUNCHOOK_BUILD_TESTS OFF CACHE BOOL "build static library")
set(FUNCHOOK_INSTALL OFF CACHE BOOL "Build tests")
set(FUNCHOOK_DISASM zydis CACHE STRING "disassembler engine")
add_subdirectory("funchook")

project(issue_36)

add_executable(issue_36 issue_36.c)
target_link_libraries(issue_36 funchook-static)

