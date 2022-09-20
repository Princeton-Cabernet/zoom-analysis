
#set(ZOOM_ANALYSIS_TEST_UNIT_INCLUDE
#        test_packets.h)


add_executable(unit unit_main.cc ${ZOOM_ANALYSIS_TEST_UNIT_INCLUDE})
target_include_directories(unit PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(unit PUBLIC ${PROJECT_SOURCE_DIR}/test/include)
#target_include_directories(unit PUBLIC ${PCAP_INCLUDE_DIRS})
#target_link_libraries(unit ${PCAP_LIBRARIES})

add_test(NAME unit COMMAND unit WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
