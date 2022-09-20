#include <catch.h>
#include "lib/net.h"
#include "lib/zoom.h"

#include "test_packets.h"

TEST_CASE("zoom::parse_zoom_pkt_buf: parses a srv-based video packet", "[zoom][parse]") {

    auto hdr = zoom::parse_zoom_pkt_buf(test::zoom_srv_video_buf, true, false);

    CHECK(hdr.ip != nullptr);
    CHECK(hdr.udp != nullptr);
    CHECK(hdr.zoom_outer != nullptr);
    CHECK(hdr.zoom_outer[0] == zoom::SRV_MEDIA_TYPE);
    CHECK(hdr.zoom_inner != nullptr);
    CHECK(hdr.zoom_inner[0] == zoom::VIDEO_TYPE);
    CHECK(hdr.rtp != nullptr);
    CHECK(hdr.rtp->payload_type() == 98);
    CHECK(hdr.rtp->seq == htons(7715));
    CHECK(hdr.rtp->ts == htonl(4092042800));
    CHECK(hdr.rtp->ssrc == htonl(16779265));
    CHECK(hdr.rtp_ext1[0] == 0x50);
    CHECK(hdr.rtp_ext1[1] == 0x00);
    CHECK(hdr.rtp_ext1[2] == 0x00);
}

TEST_CASE("zoom::parse_zoom_pkt_buf: parses a p2p audio packet", "[zoom][parse]") {

    auto hdr = zoom::parse_zoom_pkt_buf(test::zoom_p2p_audio_buf, true, true);

    CHECK(hdr.ip != nullptr);
    CHECK(hdr.udp != nullptr);
    CHECK(hdr.zoom_outer == nullptr);
    CHECK(hdr.zoom_inner != nullptr);
    CHECK(hdr.zoom_inner[0] == zoom::AUDIO_TYPE);
    CHECK(hdr.rtp != nullptr);
    CHECK(hdr.rtp->payload_type() == 99);
    CHECK(hdr.rtp->seq == htons(26820));
    CHECK(hdr.rtp->ts == htonl(19196960));
    CHECK(hdr.rtp->ssrc == htonl(16778242));
    CHECK(hdr.rtp_ext1[0] == 0x00);
    CHECK(hdr.rtp_ext1[1] == 0x00);
    CHECK(hdr.rtp_ext1[2] == 0x00);
}

TEST_CASE("zoom::parse_zoom_pkt_buf: parses a p2p screen share packet", "[zoom][parse]") {

    auto hdr = zoom::parse_zoom_pkt_buf(test::zoom_p2p_screenshare_buf, true, true);

    CHECK(hdr.ip != nullptr);
    CHECK(hdr.udp != nullptr);
    CHECK(hdr.zoom_outer == nullptr);
    CHECK(hdr.zoom_inner != nullptr);
    CHECK(hdr.zoom_inner[0] == zoom::P2P_SCREEN_SHARE_TYPE);
    CHECK(hdr.rtp != nullptr);
    CHECK(hdr.rtp->payload_type() == 99);
    CHECK(hdr.rtp->seq == htons(57697));
    CHECK(hdr.rtp->ts == htonl(2123614708));
    CHECK(hdr.rtp->ssrc == htonl(16779267));
    CHECK(hdr.rtp_ext1[0] == 0x50);
    CHECK(hdr.rtp_ext1[1] == 0x00);
    CHECK(hdr.rtp_ext1[2] == 0x00);
}

TEST_CASE("zoom::parse_zoom_pkt_buf: parses a srv-based screen share packet", "[zoom][parse]") {

    auto hdr = zoom::parse_zoom_pkt_buf(test::zoom_srv_screenshare_buf, true, false);

    CHECK(hdr.ip != nullptr);
    CHECK(hdr.udp != nullptr);
    CHECK(hdr.zoom_outer != nullptr);
    CHECK(hdr.zoom_inner != nullptr);
    CHECK(hdr.zoom_inner[0] == zoom::SRV_SCREEN_SHARE_TYPE);
    CHECK(hdr.rtp != nullptr);
    CHECK(hdr.rtp->payload_type() == 99);
    CHECK(hdr.rtp->seq == htons(7172));
    CHECK(hdr.rtp->ts == htonl(749412892));
    CHECK(hdr.rtp->ssrc == htonl(16778243));
    CHECK(hdr.rtp_ext1[0] == 0x50);
    CHECK(hdr.rtp_ext1[1] == 0x00);
    CHECK(hdr.rtp_ext1[2] == 0x00);
}

TEST_CASE("zoom::parse_zoom_pkt_buf: parses a srv-based RTCP packet", "[zoom][parse]") {

    auto hdr = zoom::parse_zoom_pkt_buf(test::zoom_srv_rtcp_buf, true, false);

    CHECK(hdr.ip != nullptr);
    CHECK(hdr.udp != nullptr);
    CHECK(hdr.zoom_outer != nullptr);
    CHECK(hdr.zoom_inner != nullptr);
    CHECK(hdr.zoom_inner[0] == zoom::RTCP_SR_SD_TYPE);
    CHECK(hdr.rtp == nullptr);
    CHECK(hdr.rtcp != nullptr);

    CHECK(hdr.rtcp->version() == 2);
    CHECK(hdr.rtcp->padding() == 0);
    CHECK(hdr.rtcp->recep_rep_count() == 0);
    CHECK(hdr.rtcp->pt == 200);
    CHECK(hdr.rtcp->ssrc == ntohl(16778242));

    // sender report (pt == 200) specific:
    CHECK(hdr.rtcp->msg.sr.ntp_ts_msw == ntohl(3841332067));
    CHECK(hdr.rtcp->msg.sr.ntp_ts_lsw == ntohl(2542320776));
    CHECK(hdr.rtcp->msg.sr.rtp_ts == ntohl(11336480));
    CHECK(hdr.rtcp->msg.sr.sender_pkt_count == ntohl(3438));
    CHECK(hdr.rtcp->msg.sr.sender_byte_count == ntohl(231506));
}

TEST_CASE("zoom::parse_zoom_pkt_buf: parses a P2P RTCP packet", "[zoom][parse]") {

    auto hdr = zoom::parse_zoom_pkt_buf(test::zoom_p2p_rtcp_buf, true, true);

    CHECK(hdr.ip != nullptr);
    CHECK(hdr.udp != nullptr);
    CHECK(hdr.zoom_outer == nullptr);
    CHECK(hdr.zoom_inner != nullptr);
    CHECK(hdr.zoom_inner[0] == zoom::RTCP_SR_SD_TYPE);
    CHECK(hdr.rtp == nullptr);
    CHECK(hdr.rtcp != nullptr);

    CHECK(hdr.rtcp->version() == 2);
    CHECK(hdr.rtcp->padding() == 0);
    CHECK(hdr.rtcp->recep_rep_count() == 0);
    CHECK(hdr.rtcp->pt == 200);
    CHECK(hdr.rtcp->ssrc == ntohl(16779266));

    // sender report (pt == 200) specific:
    CHECK(hdr.rtcp->msg.sr.ntp_ts_msw == ntohl(3841332528));
    CHECK(hdr.rtcp->msg.sr.ntp_ts_lsw == ntohl(3458851337));
    CHECK(hdr.rtcp->msg.sr.rtp_ts == ntohl(9088000));
    CHECK(hdr.rtcp->msg.sr.sender_pkt_count == ntohl(4854));
    CHECK(hdr.rtcp->msg.sr.sender_byte_count == ntohl(663624));
}
