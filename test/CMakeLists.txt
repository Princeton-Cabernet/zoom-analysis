
list(TRANSFORM ZOOM_ANALYSIS_LIB_SRC PREPEND ../)

set(ZOOM_ANALYSIS_TEST_SRC
    pcap_file_reader_test.cc
    rtp_test.cc
    rtp_test.cc
    zoom_nets_test.cc
    zoom_pkt_test.cc
    zoom_test.cc)

add_executable(unit unit_main.cc ${ZOOM_ANALYSIS_TEST_SRC} ${ZOOM_ANALYSIS_LIB_SRC})
target_include_directories(unit PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(unit PUBLIC ${PROJECT_SOURCE_DIR}/test/include)
target_include_directories(unit PUBLIC ${PCAP_INCLUDE_DIRS})
target_link_libraries(unit ${PCAP_LIBRARIES})

add_test(NAME unit COMMAND unit WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
