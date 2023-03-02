find_package(Lua "5.3" REQUIRED)

add_library(luabox
    src/sandbox.cpp
)
target_include_directories(luabox
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PUBLIC # TODO make private
        ${LUA_INCLUDE_DIR}

    message(STATUS "Lua include dir: ${LUA_INCLUDE_DIR}")
)
