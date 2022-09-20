
#include <catch.h>
#include "lib/net.h"
#include "lib/zoom.h"
#include "lib/pcap_util.h"
#include "lib/pcap_file_reader.h"
#include "lib/simple_binary_writer.h"
#include "lib/simple_binary_reader.h"

#include "test_packets.h"

TEST_CASE("zoom::pkt: is initialized with empty fields", "[zoom][pkt]") {

    zoom::pkt p;

    CHECK(p.ts.s == 0);
    CHECK(p.ts.us == 0);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 0);
    CHECK(p.flags.rtp == 0);
    CHECK(p.flags.rtcp == 0);
    CHECK(p.flags.to_srv == 0);
    CHECK(p.flags.from_srv == 0);

    CHECK(p.zoom_srv_type == 0);
    CHECK(p.zoom_media_type == 0);
    CHECK(p.pkts_in_frame == 0);
    CHECK(p.udp_pl_len == 0);

    CHECK(p.ip_5t.ip_src == 0);
    CHECK(p.ip_5t.ip_dst == 0);
    CHECK(p.ip_5t.tp_src == 0);
    CHECK(p.ip_5t.tp_dst == 0);
    CHECK(p.ip_5t.ip_proto == 0);

    CHECK(p.proto.rtp.ssrc == 0);
    CHECK(p.proto.rtp.ts == 0);
    CHECK(p.proto.rtp.seq == 0);
    CHECK(p.proto.rtp.pt == 0);

    CHECK(p.rtp_ext1[0] == 0);
    CHECK(p.rtp_ext1[1] == 0);
    CHECK(p.rtp_ext1[2] == 0);

    CHECK(p.proto.rtcp.ssrc == 0);
    CHECK(p.proto.rtcp.pt == 0);

    CHECK(sizeof(p) == 56);
}

TEST_CASE("zoom::pkt: can be initialized from rtp headers", "[zoom][pkt]") {

    auto h = zoom::parse_zoom_pkt_buf(test::zoom_srv_video_buf, true, false);
    zoom::pkt p(h, {1, 2}, false);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 1);
    CHECK(p.flags.rtp == 1);
    CHECK(p.flags.rtcp == 0);
    CHECK(p.flags.to_srv == 0);
    CHECK(p.flags.from_srv == 1);

    CHECK(p.proto.rtp.ssrc == 16779265);
    CHECK(p.proto.rtp.ts == 4092042800);
    CHECK(p.proto.rtp.seq == 7715);
    CHECK(p.proto.rtp.pt == 98);
}

TEST_CASE("zoom::pkt: can be initialized from rtcp headers", "[zoom][pkt]") {

    auto h = zoom::parse_zoom_pkt_buf(test::zoom_srv_rtcp_buf, true, false);
    zoom::pkt p(h, {1, 2}, false);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 1);
    CHECK(p.flags.rtp == 0);
    CHECK(p.flags.rtcp == 1);
    CHECK(p.flags.to_srv == 1);
    CHECK(p.flags.from_srv == 0);

    CHECK(p.proto.rtcp.ssrc == 16778242);
    CHECK(p.proto.rtcp.pt == 200);

    CHECK(p.proto.rtcp.rtp_ts == 11336480);
    CHECK(p.proto.rtcp.ntp_ts_msw == 3841332067);
    CHECK(p.proto.rtcp.ntp_ts_lsw == 2542320776);
}

TEST_CASE("zoom::pkt: can be initialized from rtp buffers with short format", "[zoom][pkt]") {

    auto h = zoom::parse_zoom_pkt_buf(test::zoom_srv_video_short_buf, true, false);
    zoom::pkt p(h, {1, 2}, false);

    CHECK(p.flags.p2p == 0);
    CHECK(p.flags.srv == 1);
    CHECK(p.flags.rtp == 1);
    CHECK(p.flags.rtcp == 0);
    CHECK(p.flags.to_srv == 0);
    CHECK(p.flags.from_srv == 1);

    CHECK(p.proto.rtp.ssrc == 16779266);
    CHECK(p.proto.rtp.pt == 98);
    CHECK(p.proto.rtp.ts == 740115488);
    CHECK(p.proto.rtp.seq == 1587);
}

TEST_CASE("zoom::pkt: can be initialized with a pcap packet ", "[zoom][pkt]") {

    pcap_file_reader pcap_reader("data/zoom_test.pcap");
    pcap_pkt pcap_pkt;

    pcap_reader.next(pcap_pkt);

    auto hdr = zoom::parse_zoom_pkt_buf(pcap_pkt.buf, true, true);
    zoom::pkt zoom_pkt(hdr, pcap_pkt.ts, true);

    CHECK(zoom_pkt.ts.s == 1632344358);
    CHECK(zoom_pkt.ts.us == 611365);
    CHECK(zoom_pkt.flags.p2p == 1);
    CHECK(zoom_pkt.flags.srv == 0);
    CHECK(zoom_pkt.flags.to_srv == 0);
    CHECK(zoom_pkt.flags.from_srv == 0);

    CHECK(zoom_pkt.ip_5t.ip_src == 0xa09791c);
    CHECK(zoom_pkt.ip_5t.ip_dst == 0xa094aac);
    CHECK(zoom_pkt.ip_5t.tp_src == 50508);
    CHECK(zoom_pkt.ip_5t.tp_dst == 64904);
    CHECK(zoom_pkt.ip_5t.ip_proto == 17);

    CHECK(zoom_pkt.udp_pl_len == 1263);

    CHECK(zoom_pkt.zoom_srv_type == 0);
    CHECK(zoom_pkt.zoom_media_type == 16);
    CHECK(zoom_pkt.pkts_in_frame == 13);

    CHECK(zoom_pkt.flags.rtp == 1);
    CHECK(zoom_pkt.flags.rtcp == 0);

    CHECK(zoom_pkt.proto.rtp.ssrc == 16778241);
    CHECK(zoom_pkt.proto.rtp.ts == 4215577188);
    CHECK(zoom_pkt.proto.rtp.seq == 26342);
    CHECK(zoom_pkt.proto.rtp.pt == 98);

    CHECK(zoom_pkt.rtp_ext1[0] == 0x50);
    CHECK(zoom_pkt.rtp_ext1[1] == 0x00);
    CHECK(zoom_pkt.rtp_ext1[2] == 0x00);
}

TEST_CASE("zoom::pkt: can be written to and read from a file", "[zoom][pkt]") {

    simple_binary_writer<zoom::pkt> zpkt_writer("data/zoom_test.zpkt");
    pcap_file_reader pcap_reader("data/zoom_test.pcap");
    pcap_pkt pcap_pkt;

    while (pcap_reader.next(pcap_pkt)) {

        auto hdr = zoom::parse_zoom_pkt_buf(pcap_pkt.buf, true, true);
        zoom::pkt zpkt(hdr, pcap_pkt.ts, true);
        zpkt_writer.write(zpkt);
    }

    pcap_reader.close();
    zpkt_writer.close();

    simple_binary_reader<zoom::pkt> zpkt_reader("data/zoom_test.zpkt");
    zoom::pkt zoom_pkt;

    CHECK(zpkt_reader.size() == 64);

    unsigned read_count = 0;

    while (zpkt_reader.next(zoom_pkt)) {
        read_count++;

        if (read_count == 1) {
            CHECK(zoom_pkt.ts.s == 1632344358);
            CHECK(zoom_pkt.ts.us == 611365);
            CHECK(zoom_pkt.flags.p2p == 1);
            CHECK(zoom_pkt.flags.srv == 0);
            CHECK(zoom_pkt.flags.to_srv == 0);
            CHECK(zoom_pkt.flags.from_srv == 0);

            CHECK(zoom_pkt.ip_5t.ip_src == 0xa09791c);
            CHECK(zoom_pkt.ip_5t.ip_dst == 0xa094aac);
            CHECK(zoom_pkt.ip_5t.tp_src == 50508);
            CHECK(zoom_pkt.ip_5t.tp_dst == 64904);
            CHECK(zoom_pkt.ip_5t.ip_proto == 17);

            CHECK(zoom_pkt.udp_pl_len == 1263);

            CHECK(zoom_pkt.zoom_srv_type == 0);
            CHECK(zoom_pkt.zoom_media_type == 16);
            CHECK(zoom_pkt.pkts_in_frame == 13);

            CHECK(zoom_pkt.flags.rtp == 1);
            CHECK(zoom_pkt.flags.rtcp == 0);

            CHECK(zoom_pkt.proto.rtp.ssrc == 16778241);
            CHECK(zoom_pkt.proto.rtp.ts == 4215577188);
            CHECK(zoom_pkt.proto.rtp.seq == 26342);
            CHECK(zoom_pkt.proto.rtp.pt == 98);

            CHECK(zoom_pkt.rtp_ext1[0] == 0x50);
            CHECK(zoom_pkt.rtp_ext1[1] == 0x00);
            CHECK(zoom_pkt.rtp_ext1[2] == 0x00);
        }
    }

    CHECK(read_count == 64);
}
