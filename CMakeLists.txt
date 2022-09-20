
cmake_minimum_required(VERSION 3.23)
project(zoom_analysis)

set(CMAKE_CXX_STANDARD 17)

include(cmake/catch.cmake)
include(cmake/cxxopts.cmake)
include(cmake/pcap.cmake)

set(ZOOM_ANALYSIS_LIB_PCAP_SRC
    lib/pcap_file_reader.h lib/pcap_file_reader.cc
    lib/pcap_file_writer.h lib/pcap_file_writer.cc)

set(ZOOM_ANALYSIS_LIB_SRC
    lib/file_stream.h
    lib/fps_calculator.h lib/fps_calculator.cc
    lib/jitter_calculator.h lib/jitter_calculator.cc
    lib/mac_counter.h lib/mac_counter.cc
    lib/net.h lib/net.cc
    lib/ring_buffer.h
    lib/rtcp.h
    lib/rtp.h
    lib/rtp_stream_analyzer.h
    lib/simple_binary_reader.h
    lib/simple_binary_writer.h
    lib/zoom.h lib/zoom.cc
    lib/zoom_analyzer.h lib/zoom_analyzer.cc
    lib/zoom_flow_tracker.h lib/zoom_flow_tracker.cc
    lib/zoom_nets.h
    lib/zoom_offline_analyzer.h lib/zoom_offline_analyzer.cc
    lib/zoom_rtp_stream_tracker.h lib/zoom_rtp_stream_tracker.cc)


list(TRANSFORM ZOOM_ANALYSIS_LIB_PCAP_SRC PREPEND src/)
list(TRANSFORM ZOOM_ANALYSIS_LIB_SRC PREPEND src/)

#### zoom_flows:

add_executable(zoom_flows
    ${ZOOM_ANALYSIS_LIB_SRC}
    ${ZOOM_ANALYSIS_LIB_PCAP_SRC}
    src/cmd/zoom_flows.h
    src/cmd/zoom_flows_main.cc)
target_include_directories(zoom_flows PUBLIC ext/include)
target_link_libraries(zoom_flows ${PCAP_LIBRARIES})
set_target_properties(zoom_flows PROPERTIES LINKER_LANGUAGE CXX)

#### zoom_rtp:

add_executable(zoom_rtp
    ${ZOOM_ANALYSIS_LIB_SRC} src/cmd/zoom_rtp.h
    src/cmd/zoom_rtp_main.cc)
target_include_directories(zoom_rtp PUBLIC ext/include)
set_target_properties(zoom_rtp PROPERTIES LINKER_LANGUAGE CXX)

#### unit testing:

enable_testing()
add_subdirectory(test)
