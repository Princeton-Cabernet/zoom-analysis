
cmake_minimum_required(VERSION 3.23)
project(zoom_analysis)

set(CMAKE_CXX_STANDARD 17)

include(cmake/catch.cmake)
include(cmake/cxxopts.cmake)
include(cmake/pcap.cmake)

set(ZOOM_ANALYSIS_LIB_SRC
    lib/file_stream.h
    lib/net.h lib/net.cc
    lib/pcap_file_reader.h lib/pcap_file_reader.cc
    lib/pcap_file_writer.h lib/pcap_file_writer.cc
    lib/rtcp.h
    lib/rtp.h
    lib/simple_binary_reader.h
    lib/simple_binary_writer.h
    lib/zoom.h lib/zoom.cc
    lib/zoom_nets.h
)

list(TRANSFORM ZOOM_ANALYSIS_LIB_SRC PREPEND src/)

#### unit testing:

enable_testing()
add_subdirectory(test)
