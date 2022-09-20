
cmake_minimum_required(VERSION 3.23)
project(zoom_analysis)

set(CMAKE_CXX_STANDARD 20)

include(cmake/catch.cmake)
include(cmake/cxxopts.cmake)
include(cmake/pcap.cmake)

set(ZOOM_ANALYSIS_LIB_SRC
    lib/net.h lib/net.cc
    lib/rtcp.h
    lib/rtp.h
    lib/zoom.h lib/zoom.cc
    lib/zoom_nets.h
)

list(TRANSFORM ZOOM_ANALYSIS_LIB_SRC PREPEND src/)

#### unit testing:

enable_testing()
add_subdirectory(test)
