add_executable(luabox_test
    test.cpp
)
target_link_libraries(luabox_test
    luabox
    gtest_main
)
gtest_discover_tests(luabox_test)
