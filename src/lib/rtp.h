
#ifndef ZOOM_ANALYSIS_RTP_H
#define ZOOM_ANALYSIS_RTP_H

#include "net.h"

#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <vector>

namespace rtp {

    static const unsigned HDR_LEN = 12;

    struct hdr {

        // https://datatracker.ietf.org/doc/html/rfc3550#section-5.1

        std::uint8_t  v_p_x_cc = 0;
        std::uint8_t  m_pt     = 0;
        std::uint16_t seq      = 0;
        std::uint32_t ts       = 0;
        std::uint32_t ssrc     = 0;

        [[nodiscard]] unsigned version() const {
            return (v_p_x_cc >> 6) & 0x03;
        }

        [[nodiscard]] unsigned padding() const {
            return (v_p_x_cc >> 5) & 0x01;
        }

        [[nodiscard]] unsigned extension() const {
            return (v_p_x_cc >> 4) & 0x01;
        }

        [[nodiscard]] unsigned csrc_count() const {
            return v_p_x_cc & 0x0f;
        }

        [[nodiscard]] unsigned marker() const {
            return m_pt >> 6 & 0x01;
        }

        [[nodiscard]] unsigned payload_type() const {
            return m_pt & 0x7f;
        }
    };

    static std::ostream& operator<<(std::ostream& os, const rtp::hdr& rtp) {
        os << "rtp: v=" << std::dec << rtp.version()
            << ",p=" << std::dec << rtp.padding()
            << ",x=" << std::dec << rtp.extension()
            << ",cc=" << std::dec << rtp.csrc_count()
            << ",m=" << std::dec << rtp.marker()
            << ",pt=" << std::dec << rtp.payload_type()
            << ",seq=" << std::dec << ntohs(rtp.seq)
            << ",ts=" << std::dec << ntohl(rtp.ts)
            << ",ssrc=0x" << std::hex << std::setw(8) << std::setfill('0')
            << ntohl(rtp.ssrc) << std::dec;

        return os;
    }

    struct ext {
        struct header {
            unsigned short type = 0, len = 0;
            unsigned char data[16] = {0};

            bool operator==(const struct header& other) const {
                return type == other.type && len == other.len
                        && std::strncmp((const char*) data, (const char*) other.data, len) == 0;
            }

            inline bool operator!=(const struct header& other) const {
                return !(*this == other);
            }
        };

        unsigned short count = 0;
        unsigned short bytes = 0;
        struct header headers[8] = {};
    };

    static void parse_ext_headers(const unsigned char* rtp_ext_ptr, struct ext& ext) {

        unsigned ext_i = 0;

        ext.bytes =  (rtp_ext_ptr[2] << 8) + (rtp_ext_ptr[3]) * 4;

        for (auto ext_byte_i = 4; ext_byte_i < 4 + ext.bytes;) {
            if (rtp_ext_ptr[ext_byte_i] != 0) { // 0 -> padding byte
                ext.headers[ext_i].type = (rtp_ext_ptr[ext_byte_i] >> 4) & 0x0f;
                // +1 for undercounting in len field:
                ext.headers[ext_i].len = (rtp_ext_ptr[ext_byte_i] & 0x0f) + 1;
                std::memcpy(ext.headers[ext_i].data, rtp_ext_ptr + ext_byte_i + 1,
                            ext.headers[ext_i].len);
                ext_byte_i += (ext.headers[ext_i].len + 1); // +1 for extension element header
                ext_i++;
            } else {
                ext_byte_i++;
            }
        }

        ext.count = ext_i;
    }

    static struct ext::header get_ext_header(const struct ext& rtp_ext, unsigned type) {

        struct ext::header h;

        for (auto i = 0; i < rtp_ext.count; i++) {
            if (rtp_ext.headers[i].type == type) {
                h = rtp_ext.headers[i];
                break;
            } else {
                h.len = 0;
            }
        }

        return h;
    }

    static std::string ext_str(const struct rtp::ext::header& h) {

        std::stringstream ss;
        ss << std::hex << std::setw(2) << std::setfill('0') << "0x";

        for (auto i = 0; i < h.len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0')
               << (unsigned) h.data[i];
        }

        return ss.str();
    };

}

#endif
