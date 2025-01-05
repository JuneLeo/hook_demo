cmake_minimum_required(VERSION 3.22.1)

project("call")

set(CMAKE_BUILD_TYPE Debug)

add_library(dobby STATIC IMPORTED)

set_target_properties(dobby PROPERTIES IMPORTED_LOCATION
       ${PROJECT_SOURCE_DIR}/static/dobby/libdobby.a)

add_library(call SHARED
        native-lib.cpp)

target_include_directories(call PUBLIC ${PROJECT_SOURCE_DIR}/static/dobby/include)

target_link_libraries(call
        dobby
        android
        log)


add_library(hook SHARED
        hook/hook.cpp
        hook/elf_parse.cpp
        hook/elf_parse.h
        hook/log.h)

target_link_libraries(hook
        android
        log)








