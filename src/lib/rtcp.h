
#ifndef ZOOM_ANALYSIS_RTCP_H
#define ZOOM_ANALYSIS_RTCP_H

#include "net.h"

#include <arpa/inet.h>
#include <iomanip>

namespace rtcp {

    struct hdr {

        // https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.1
        // https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.2

        std::uint8_t v_p_rc = 0;
        std::uint8_t pt     = 0;
        std::uint16_t len   = 0;
        std::uint32_t ssrc  = 0;

        [[nodiscard]] unsigned version() const {
            return (v_p_rc >> 6) & 0x03;
        }

        [[nodiscard]] unsigned padding() const {
            return (v_p_rc >> 5) & 0x01;
        }

        [[nodiscard]] unsigned recep_rep_count() const {
            return v_p_rc & 0x1f;
        }

        struct sr {
            std::uint32_t ntp_ts_msw        = 0;
            std::uint32_t ntp_ts_lsw        = 0;
            std::uint32_t rtp_ts            = 0;
            std::uint32_t sender_pkt_count  = 0;
            std::uint32_t sender_byte_count = 0;
        };

        union msg {
            struct sr sr;
        };

        msg msg;
    };

    static std::ostream &operator<<(std::ostream &os, const rtcp::hdr &rtcp) {
        os << "rtcp: v="  << std::dec << rtcp.version()
           << ",p="      << std::dec << rtcp.padding()
           << ",rc="     << std::dec << rtcp.recep_rep_count()
           << ",pt="     << std::dec << (unsigned) rtcp.pt
           << ",len="    << std::dec << ntohs(rtcp.len)
           << ",ssrc=0x" << std::hex << std::setw(8) << std::setfill('0')
                << ntohl(rtcp.ssrc) << std::dec;

        return os;
    }
}

#endif
