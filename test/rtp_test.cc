
#include <catch.h>
#include <arpa/inet.h>

#include "lib/rtp.h"
#include "test_packets.h"

TEST_CASE("rtp", "[rtp]") {

    auto rtp = (rtp::hdr*) (test::rtp_buf1 + 32);

    CHECK(rtp->version() == 2);
    CHECK(rtp->padding() == 0);
    CHECK(rtp->extension() == 1);
    CHECK(rtp->csrc_count() == 0);
    CHECK(rtp->marker() == 1);
    CHECK(rtp->payload_type() == 104);
    CHECK(ntohs(rtp->seq) == 20223);
    CHECK(ntohl(rtp->ts) == 2941283823);
    CHECK(ntohl(rtp->ssrc) == 0x6a70d0e8);

    struct rtp::ext ext{};
    rtp::parse_ext_headers(test::rtp_buf1 + 32 + 12, ext);

    CHECK(ext.count == 4);
    CHECK(ext.bytes == 12);
    CHECK(ext.headers[0].type == 2);
    CHECK(ext.headers[0].len == 3);
    CHECK(ext.headers[0].data[0] == 0xa7);
    CHECK(ext.headers[0].data[1] == 0x70);
    CHECK(ext.headers[0].data[2] == 0xa4);
    CHECK(ext.headers[1].type == 3);
    CHECK(ext.headers[1].len == 2);
    CHECK(ext.headers[1].data[0] == 0x00);
    CHECK(ext.headers[1].data[1] == 0x07);
    CHECK(ext.headers[2].type == 4);
    CHECK(ext.headers[2].len == 1);
    CHECK(ext.headers[2].data[0] == 0x30);
    CHECK(ext.headers[3].type == 13);
    CHECK(ext.headers[3].len == 1);
    CHECK(ext.headers[3].data[0] == 0x00);
}
