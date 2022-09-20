
cmake_minimum_required(VERSION 3.23)
project(zoom_analysis)

set(CMAKE_CXX_STANDARD 17)

include(cmake/catch.cmake)
include(cmake/cxxopts.cmake)
include(cmake/pcap.cmake)

set(ZOOM_ANALYSIS_LIB_SRC
    lib/file_stream.h
    lib/mac_counter.h lib/mac_counter.cc
    lib/net.h lib/net.cc
    lib/pcap_file_reader.h lib/pcap_file_reader.cc
    lib/pcap_file_writer.h lib/pcap_file_writer.cc
    lib/rtcp.h
    lib/rtp.h
    lib/simple_binary_reader.h
    lib/simple_binary_writer.h
    lib/zoom.h lib/zoom.cc
    lib/zoom_flow_tracker.h lib/zoom_flow_tracker.cc
    lib/zoom_nets.h)


list(TRANSFORM ZOOM_ANALYSIS_LIB_SRC PREPEND src/)

#### zoom_flows:

add_executable(zoom_flows ${ZOOM_ANALYSIS_LIB_SRC} src/cmd/zoom_flows.h src/cmd/zoom_flows_main.cc)
target_include_directories(zoom_flows PUBLIC ext/include)
target_link_libraries(zoom_flows ${PCAP_LIBRARIES})
set_target_properties(zoom_flows PROPERTIES LINKER_LANGUAGE CXX)

#### unit testing:

enable_testing()
add_subdirectory(test)
