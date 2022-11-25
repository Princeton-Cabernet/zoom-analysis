#ifndef ZOOM_ANALYSIS_ZOOM_H
#define ZOOM_ANALYSIS_ZOOM_H

#include <arpa/inet.h>

#include "rtp.h"
#include "rtcp.h"

namespace zoom {

    const std::uint8_t SRV_MEDIA_TYPE        = 0x05;
    const std::uint8_t AUDIO_TYPE            = 0x0f;
    const std::uint8_t VIDEO_TYPE            = 0x10;
    const std::uint8_t SRV_SCREEN_SHARE_TYPE = 0x0d;
    const std::uint8_t P2P_SCREEN_SHARE_TYPE = 0x1e;
    const std::uint8_t RTCP_SR_TYPE          = 0x21;
    const std::uint8_t RTCP_SR_SD_TYPE       = 0x22;

    struct headers {
        const net::ipv4::hdr* ip        = nullptr;
        const net::udp::hdr* udp        = nullptr;
        const unsigned char* zoom_inner = nullptr;
        const unsigned char* zoom_outer = nullptr;
        const rtp::hdr* rtp             = nullptr;
        const rtcp::hdr* rtcp           = nullptr;
        unsigned char rtp_ext1[3]       = {0};

        unsigned udp_pl_offset          = 0;
        unsigned rtp_rtcp_offset        = 0;
    };

    struct pkt {

        pkt();
        pkt(const struct zoom::headers& hdr, timeval tv, bool is_p2p);
        pkt(const pkt&) = default;
        pkt& operator=(const pkt&) = default;

        struct ts {
            std::uint32_t s  = 0;
            std::uint32_t us = 0;
        };

        struct flags {
            std::uint8_t p2p      : 1;
            std::uint8_t srv      : 1;
            std::uint8_t rtp      : 1;
            std::uint8_t rtcp     : 1;
            std::uint8_t to_srv   : 1;
            std::uint8_t from_srv : 1;
            std::uint8_t pad      : 2;
        };

        struct rtp_data { // 12 Bytes
            std::uint32_t ssrc   = 0;
            std::uint32_t ts     = 0;
            std::uint16_t seq    = 0;
            std::uint8_t  pt     = 0;
            std::uint8_t  pad    = 0;
        };

        struct rtcp_data { // 20 Bytes
            std::uint32_t ssrc       = 0;
            std::uint8_t  pt         = 0;
            std::uint8_t  pad[3]     = {0};
            std::uint32_t rtp_ts     = 0;
            std::uint32_t ntp_ts_msw = 0;
            std::uint32_t ntp_ts_lsw = 0;

        };

        union proto_data {
            rtp_data rtp;
            rtcp_data rtcp;
        };

        ts ts                        = {};  //  8 Bytes
        net::ipv4_5tuple ip_5t       = {};  // 16 Bytes
        flags flags                  = {};  //  1 Byte
        std::uint8_t zoom_srv_type   = 0;   //  1 Byte
        std::uint8_t zoom_media_type = 0;   //  1 Byte
        std::uint16_t pkts_in_frame  = 0;   //  2 Bytes
        std::uint16_t udp_pl_len     = 0;   //  2 Bytes

        proto_data proto             = {};   // 12 Bytes
        std::uint8_t rtp_ext1[3]     = {0}; // 3 Bytes
        std::uint8_t pad             = 0;   // 1 Byte
    };

    static_assert(sizeof(struct zoom::pkt) == 56);

    enum class media_type : std::uint8_t {
        audio  = 0,
        video  = 1,
        screen = 2
    };

    static char media_type_to_char(media_type t);

    enum class stream_type : std::uint8_t {
        media = 0,
        fec   = 1
    };

    static char stream_type_to_char(stream_type t);

    struct media_stream_key {
        net::ipv4_5tuple ip_5t = {};
        std::uint32_t rtp_ssrc = 0;
        enum media_type media_type;
        enum stream_type stream_type;

        static media_stream_key from_pkt(const pkt& pkt);
        bool operator<(const struct media_stream_key& a) const;
        bool operator==(const struct media_stream_key& a) const;
    };

    struct rtp_stream_key {
        net::ipv4_5tuple ip_5t = {};
        std::uint32_t rtp_ssrc = 0;
        std::uint8_t  rtp_pt   = 0;

        static rtp_stream_key from_pkt(const pkt& pkt);

        bool operator<(const struct rtp_stream_key& a) const;
        bool operator==(const struct rtp_stream_key& a) const;
    };

    struct rtp_stream_meta {
        net::ipv4_5tuple ip_5t  = {};
        std::uint32_t rtp_ssrc  = 0;
        std::uint8_t rtp_pt     = 0;
        std::uint8_t media_type = 0;

        static rtp_stream_meta from_pkt(const pkt& pkt);
    };

    struct rtp_pkt_meta {
        std::uint8_t rtp_ext1[3]  = {0, 0, 0};
        std::uint8_t pkt_type     = 0;
        unsigned pkts_hint        = 0;
    };

    [[nodiscard]] struct headers parse_zoom_pkt_buf(const unsigned char* buf,
            bool includes_eth = true, bool is_p2p = false);
}

#endif
