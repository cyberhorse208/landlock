cmake_minimum_required(VERSION 3.10.2)

project("landlock")

# 接收 landlock 版本参数，默认为 6.18
if(NOT DEFINED LANDLOCK_VERSION)
    set(LANDLOCK_VERSION "6.18")
endif()

message(STATUS "Building landlock version: ${LANDLOCK_VERSION}")

# 设置源文件路径
set(LANDLOCK_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/landlock/${LANDLOCK_VERSION}")

# 检查目录是否存在
if(NOT EXISTS "${LANDLOCK_SRC_DIR}")
    message(FATAL_ERROR "Landlock version ${LANDLOCK_VERSION} not found at ${LANDLOCK_SRC_DIR}")
endif()

# 编译 landlock 库
add_library(landlock SHARED
    ${LANDLOCK_SRC_DIR}/landlock-jni.cpp
)

# 链接日志库
find_library(log-lib log)
target_link_libraries(landlock ${log-lib})

# 设置编译选项
target_compile_options(landlock PRIVATE -std=c++17)
