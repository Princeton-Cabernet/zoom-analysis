
#include <catch.h>
#include "lib/net.h"
#include "lib/pcap_util.h"
#include "lib/pcap_file_reader.h"

TEST_CASE("pcap_file_reader: single input file", "[pcap][pcap_file_reader]") {

    pcap_file_reader r("data/test0.pcap");

    SECTION("next(buf, ...)") {

        const unsigned char* buf = nullptr;
        timeval ts = {0, 0};
        unsigned short frame_len = 0, cap_len = 0;
        unsigned total_frames = 0, total_bytes = 0;

        CHECK(r.next(&buf, ts, frame_len, cap_len));
        total_frames++;
        total_bytes += frame_len;

        CHECK(ts.tv_sec == 1646581842);
        CHECK(frame_len == 78);
        CHECK(cap_len == 64);
        CHECK(buf[0] == 0xbc);

        while (r.next(&buf, ts, frame_len, cap_len)) {
            total_frames++;
            total_bytes += frame_len;
        }

        CHECK(ts.tv_sec == 1646581842);
        CHECK(frame_len == 66);
        CHECK(cap_len == 64);
        CHECK(buf[0] == 0xb2);

        CHECK(total_frames == 10);
        CHECK(total_bytes == 795);
    }

    SECTION("next(pcap_pkt)") {

        pcap_pkt pkt;
        unsigned total_frames = 0, total_bytes = 0;

        CHECK(r.next(pkt));
        total_frames++;
        total_bytes += pkt.frame_len;

        CHECK(pkt.ts.tv_sec == 1646581842);
        CHECK(pkt.frame_len == 78);
        CHECK(pkt.cap_len == 64);
        CHECK(pkt.buf[0] == 0xbc);

        while (r.next(pkt)) {
            total_frames++;
            total_bytes += pkt.frame_len;
        }

        CHECK(pkt.ts.tv_sec == 1646581842);
        CHECK(pkt.frame_len == 66);
        CHECK(pkt.cap_len == 64);
        CHECK(pkt.buf[0] == 0xb2);

        CHECK(total_frames == 10);
        CHECK(total_bytes == 795);
    }

    r.close();
}

TEST_CASE("pcap_file_reader: multiple input files", "[pcap][pcap_file_reader]") {

    std::vector<std::string> file_names = {
        "data/test0.pcap",
        "data/test1.pcap",
        "data/test2.pcap",
        "data/test3.pcap",
        "data/test4.pcap",
        "data/test5.pcap",
        "data/test6.pcap",
        "data/test7.pcap"
    };


    pcap_file_reader p(file_names);

    CHECK(p.datalink_type() == pcap_link_type::eth);

    SECTION("next(pcap_pkt)") {

        pcap_pkt pkt;
        unsigned total_frames = 0, total_bytes = 0;

        while (p.next(pkt)) {
            total_frames++;
            total_bytes += pkt.frame_len;
        }

        CHECK(total_frames == 80);
        CHECK(total_bytes == 7203);
    }

    p.close();
}

TEST_CASE("pcap_file_reader: throws an exception when providing inconsistent data link types",
          "[pcap][pcap_file_reader]") {

    std::vector<std::string> inconsistent_data_links = {
        "data/test3.pcap",
        "data/test4_rawip.pcap",
        "data/test5.pcap"
    };

    pcap_file_reader* p = nullptr;

    CHECK_THROWS(p = new pcap_file_reader(inconsistent_data_links));
}
