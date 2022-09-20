
#include <catch.h>
#include <arpa/inet.h>

#include "lib/rtcp.h"
#include "test_packets.h"

TEST_CASE("rtcp: can be parsed from a packet buffer", "[rtcp]") {

    auto rtcp = (rtcp::hdr*) (test::rtp_sr_buf);

    // rtcp common header:
    CHECK(rtcp->version() == 2);
    CHECK(rtcp->padding() == 0);
    CHECK(rtcp->recep_rep_count() == 0);
    CHECK(rtcp->pt == 200);
    CHECK(rtcp->ssrc == ntohl(16778241));

    // sender report (pt == 200) specific:
    CHECK(rtcp->msg.sr.ntp_ts_msw == ntohl(3841332586));
    CHECK(rtcp->msg.sr.ntp_ts_lsw == ntohl(1674737310));
    CHECK(rtcp->msg.sr.rtp_ts == ntohl(4164197538));
    CHECK(rtcp->msg.sr.sender_pkt_count == ntohl(102777));
    CHECK(rtcp->msg.sr.sender_byte_count == ntohl(119018945));
}
