cmake_minimum_required(VERSION 3.24)

project(p256-cortex-m4)

project(${PROJECT_NAME} C ASM)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 17)

add_library(${PROJECT_NAME} p256-cortex-m4.c p256-cortex-m4-asm-gcc.S)

target_include_directories(${PROJECT_NAME} PUBLIC Inc)
