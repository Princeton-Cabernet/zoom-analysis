
#include <catch.h>
#include <lib/net.h>
#include <lib/zoom_nets.h>

#include "test_packets.h"

TEST_CASE("zoom::nets", "[zoom][nets]") {

    // check examples for four networks (one match / one mismatch)
    // 3.25.49.0/24
    // 13.52.6.128/25
    // 147.124.96.0/19
    // 209.9.215.0/24

    CHECK(zoom::nets::match(net::ipv4::str_to_addr("3.25.49.22")));
    CHECK_FALSE(zoom::nets::match(net::ipv4::str_to_addr("3.25.48.244")));
    CHECK(zoom::nets::match(net::ipv4::str_to_addr("13.52.6.140")));
    CHECK_FALSE(zoom::nets::match(net::ipv4::str_to_addr("13.52.6.110")));
    CHECK(zoom::nets::match(net::ipv4::str_to_addr("147.124.100.12")));
    CHECK_FALSE(zoom::nets::match(net::ipv4::str_to_addr("147.124.70.12")));
    CHECK(zoom::nets::match(net::ipv4::str_to_addr("209.9.215.34")));
    CHECK_FALSE(zoom::nets::match(net::ipv4::str_to_addr("209.9.216.3")));
}
