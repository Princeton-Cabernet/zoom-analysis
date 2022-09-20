
set(CATCH_VERSION 2.13.8)

if (NOT EXISTS ${CMAKE_HOME_DIRECTORY}/test/include/catch.h)
    file(DOWNLOAD
            https://github.com/catchorg/Catch2/releases/download/v${CATCH_VERSION}/catch.hpp
            ${CMAKE_HOME_DIRECTORY}/test/include/catch.h)
    message(STATUS "Downloading Catch: /test/include/catch.h - done")
endif ()
