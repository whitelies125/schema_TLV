cmake_minimum_required(VERSION 3.20)
project(schema_TLV LANGUAGES C CXX)

include(CTest)

add_library(tlv_c STATIC codec/c/tlv.c)
target_include_directories(tlv_c PUBLIC "${PROJECT_SOURCE_DIR}/codec/c" "${PROJECT_SOURCE_DIR}/codec")
set_target_properties(tlv_c PROPERTIES
    C_STANDARD 99 C_STANDARD_REQUIRED YES C_EXTENSIONS NO
)

add_library(tlv_cpp STATIC codec/cpp/tlv.cpp)
target_include_directories(tlv_cpp PUBLIC "${PROJECT_SOURCE_DIR}/codec/cpp" "${PROJECT_SOURCE_DIR}/codec")
target_compile_features(tlv_cpp PUBLIC cxx_std_23)
set_target_properties(tlv_cpp PROPERTIES CXX_EXTENSIONS NO)

# 两版示例使用同一份消息和 schema，分别链接独立的编解码库。
add_executable(demo demo/schema/msg_demo.cpp demo/c/demo.cpp)
target_include_directories(demo PRIVATE demo/schema)
target_link_libraries(demo PRIVATE tlv_c)
set_target_properties(demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/$<0:>"
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
)
if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(demo PRIVATE stdc++exp)
endif()

add_executable(demo_cpp demo/schema/msg_demo.cpp demo/cpp/demo_cpp.cpp)
target_include_directories(demo_cpp PRIVATE demo/schema)
target_link_libraries(demo_cpp PRIVATE tlv_cpp)
set_target_properties(demo_cpp PROPERTIES CXX_EXTENSIONS NO)

foreach(codec_target IN ITEMS tlv_c tlv_cpp demo demo_cpp)
    if(MSVC)
        target_compile_options(${codec_target} PRIVATE /W4)
    else()
        target_compile_options(${codec_target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endforeach()

if(BUILD_TESTING)
    add_executable(tlv_cpp_test demo/schema/msg_demo.cpp test/cpp/tlv_cpp_test.cpp)
    target_include_directories(tlv_cpp_test PRIVATE demo/schema)
    target_link_libraries(tlv_cpp_test PRIVATE tlv_cpp tlv_c)
    set_target_properties(tlv_cpp_test PROPERTIES CXX_EXTENSIONS NO)

    add_executable(tlv_cpp_allocation_test test/cpp/tlv_cpp_allocation_test.cpp)
    target_link_libraries(tlv_cpp_allocation_test PRIVATE tlv_cpp)
    set_target_properties(tlv_cpp_allocation_test PROPERTIES CXX_EXTENSIONS NO)

    add_test(NAME tlv_c_demo COMMAND demo)
    add_test(NAME tlv_cpp_compatibility COMMAND tlv_cpp_test)
    add_test(NAME tlv_cpp_demo COMMAND demo_cpp)
    add_test(NAME tlv_cpp_allocation COMMAND tlv_cpp_allocation_test)
endif()
