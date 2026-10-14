cmake_minimum_required(VERSION 3.20)
project(schema_TLV LANGUAGES C CXX)

add_executable(demo
    codec/tlv.c
    schema/msg_demo.cpp
    test/demo.cpp
)
target_include_directories(demo PRIVATE codec schema)
set_target_properties(demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<0:>"
    C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
)
if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(demo PRIVATE stdc++exp)
endif()
if(MSVC)
    target_compile_options(demo PRIVATE /W4)
else()
    target_compile_options(demo PRIVATE -Wall -Wextra -Wpedantic)
endif()
