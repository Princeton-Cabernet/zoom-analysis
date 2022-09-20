
find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)

if (PCAP_FOUND)
    message(STATUS "Detecting libpcap - done
   PCAP_INCLUDE_DIRS: ${PCAP_INCLUDE_DIRS}
   PCAP_LIBRARIES: ${PCAP_LIBRARIES}
   PCAP_LINK_LIBRARIES: ${PCAP_LINK_LIBRARIES}
   PCAP_VERSION: ${PCAP_VERSION}")
else ()
    message(FATAL_ERROR "Could not find libpcap")
endif ()
