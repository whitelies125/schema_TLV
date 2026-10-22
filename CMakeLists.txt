cmake_minimum_required(VERSION 3.20)
project(schema_TLV LANGUAGES C CXX)

# 仅传递源码、头文件目录和语言要求；源码由使用方目标直接编译，不生成独立库文件。
add_library(tlv_c INTERFACE)
target_sources(tlv_c INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/codec/c/tlv.c")
target_include_directories(tlv_c INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/codec")
target_compile_features(tlv_c INTERFACE c_std_99)

add_library(tlv_cpp INTERFACE)
target_sources(tlv_cpp INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/codec/cpp/tlv.cpp")
target_include_directories(tlv_cpp INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/codec")
target_compile_features(tlv_cpp INTERFACE cxx_std_23)

# 作为子目录引入时只提供源码目标；示例和测试仅在独立构建本项目时创建。
if(NOT CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    return()
endif()

include(CTest)

# 两版示例使用同一份消息和 schema，分别直接编译对应版本的编解码源码。
add_executable(demo demo/schema/msg_demo.cpp demo/c/demo.cpp)
target_include_directories(demo PRIVATE demo/schema)
target_link_libraries(demo PRIVATE tlv_c)
set_target_properties(demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/$<0:>"
    C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
)
if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(demo PRIVATE stdc++exp)
endif()

add_executable(demo_cpp demo/schema/msg_demo.cpp demo/cpp/demo_cpp.cpp)
target_include_directories(demo_cpp PRIVATE demo/schema)
target_link_libraries(demo_cpp PRIVATE tlv_cpp)
set_target_properties(demo_cpp PROPERTIES CXX_EXTENSIONS NO)

foreach(codec_target IN ITEMS demo demo_cpp)
    if(MSVC)
        target_compile_options(${codec_target} PRIVATE /W4)
    else()
        target_compile_options(${codec_target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endforeach()

if(BUILD_TESTING)
    add_executable(test_cpp demo/schema/msg_demo.cpp test/cpp/test_cpp.cpp)
    target_include_directories(test_cpp PRIVATE demo/schema)
    target_link_libraries(test_cpp PRIVATE tlv_cpp tlv_c)
    set_target_properties(test_cpp PROPERTIES
        C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO CXX_EXTENSIONS NO
    )

    add_executable(test_c test/c/test_c.c)
    target_link_libraries(test_c PRIVATE tlv_c)
    set_target_properties(test_c PROPERTIES
        C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
    )

    add_test(NAME test_c COMMAND test_c)
    add_test(NAME test_cpp COMMAND test_cpp)
endif()
