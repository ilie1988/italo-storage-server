cmake_minimum_required (VERSION 3.1)

add_executable (Test
    main.cpp
    storage.cpp
    pow.cpp
    serialization.cpp
    signature.cpp
    rate_limiter.cpp
    command_line.cpp
)

# library under test

italo_add_subdirectory(../common common)
italo_add_subdirectory(../storage storage)
italo_add_subdirectory(../pow pow)
italo_add_subdirectory(../utils utils)
italo_add_subdirectory(../crypto crypto)
italo_add_subdirectory(../httpserver httpserver)

target_link_libraries(Test PRIVATE common storage pow utils crypto httpserver_lib)

# boost
find_package(Boost REQUIRED
    system
    filesystem
    chrono
    thread
    unit_test_framework
)

set_property(TARGET Test PROPERTY CXX_STANDARD 17)
set_property(TARGET Test PROPERTY CXX_STANDARD_REQUIRED TRUE)

target_include_directories(Test PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(Test PRIVATE ${Boost_LIBRARIES})
