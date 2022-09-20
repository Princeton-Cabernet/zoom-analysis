
cmake_minimum_required(VERSION 3.23)
project(zoom_analysis)

set(CMAKE_CXX_STANDARD 20)

include(cmake/catch.cmake)

#### unit testing:

enable_testing()
add_subdirectory(test)
