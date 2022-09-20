
#ifndef ZOOM_ANALYSIS_NET_H
#define ZOOM_ANALYSIS_NET_H

#include <arpa/inet.h> // for ntohs, ntohl, etc.

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>

namespace net {

    /*
    //! reverses the byte order of a 2 Byte unsigned integer
    //!
    inline uint16_t reverse_byte_order_short(std::uint16_t a) {
        return ((a & 0xff00) >> 8u)
               | ((a & 0x00ff) << 8u);
    }

    //! reverses the byte order of a 4 Byte unsigned integer
    //!
    inline uint32_t reverse_byte_order(std::uint32_t a) {
        return ((a & 0xff000000u) >> 24u)
               | ((a & 0x00ff0000u) >>  8u)
               | ((a & 0x0000ff00u) <<  8u)
               | ((a & 0x000000ffu) << 24u);
    }

    //! reverses the byte order of a 8 Byte unsigned integer
    //!
    inline uint64_t reverse_byte_order_long(std::uint64_t a) {
        return ((a & 0xff00000000000000u) >> 56u)
               | ((a & 0x00ff000000000000u) >> 40u)
               | ((a & 0x0000ff0000000000u) >> 24u)
               | ((a & 0x000000ff00000000u) >>  8u)
               | ((a & 0x00000000ff000000u) <<  8u)
               | ((a & 0x0000000000ff0000u) << 24u)
               | ((a & 0x000000000000ff00u) << 40u)
               | ((a & 0x00000000000000ffu) << 56u);
    }
    */

    namespace eth {

        const unsigned ADDR_LEN = 6;
        const unsigned HDR_LEN = 14;

        enum class type : std::uint16_t {
            ipv4 = 0x0800
        };

        struct addr {
            std::uint8_t bytes[ADDR_LEN] = {0};

            [[nodiscard]] std::string to_str() const {
                std::stringstream ss;
                ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned) bytes[0] << ":"
                   << std::hex << std::setw(2) << std::setfill('0') << (unsigned) bytes[1] << ":"
                   << std::hex << std::setw(2) << std::setfill('0') << (unsigned) bytes[2] << ":"
                   << std::hex << std::setw(2) << std::setfill('0') << (unsigned) bytes[3] << ":"
                   << std::hex << std::setw(2) << std::setfill('0') << (unsigned) bytes[4] << ":"
                   << std::hex << std::setw(2) << std::setfill('0') << (unsigned) bytes[5];
                return ss.str();
            }
        };

        struct hdr {
            addr dst_addr;
            addr src_addr;
            std::uint16_t ether_type = 0;
        };

        //! converts a MAC address in colon-hexadecimal notation to an eth::addr struct
        //!
        static addr str_to_addr(const std::string &s) {
            addr a = {};
            int bytes = std::sscanf(s.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                    a.bytes + 0, a.bytes + 1, a.bytes + 2, a.bytes + 3, a.bytes + 4, a.bytes + 5);

            if (bytes != ADDR_LEN)
                throw std::invalid_argument("invalid mac address");

            return a;
        }

        static type type_from_buf(const unsigned char* buf) {
            auto* eth_hdr = (hdr*) buf;
            return type{ntohs(eth_hdr->ether_type)};
        }
    }

    namespace ipv4 {

        const unsigned HDR_LEN = 20;

        enum class proto : std::uint8_t {
            tcp = 6,
            udp = 17
        };

        struct hdr { // 20
            std::uint8_t version_ihl = 0; // 1
            std::uint8_t type_of_service = 0; // 1
            std::uint16_t total_length = 0; // 2
            std::uint16_t id = 0; // 2
            std::uint16_t fragment_offset = 0; // 2 // 8
            std::uint8_t time_to_live = 0; // 1
            std::uint8_t next_proto_id = 0; // 1
            std::uint16_t hdr_checksum = 0; // 2
            std::uint32_t src_addr = 0; // 4 // 8
            std::uint32_t dst_addr = 0; // 4

            unsigned ihl_bytes() const {
                return (version_ihl & 0x0f) * 4;
            }
        };

        //! converts a 4 Byte unsigned Integer to dotted-decimal notation
        //!
        static std::string addr_to_str(const std::uint32_t &addr) {
            std::string s;
            s += std::to_string(addr >> 24u & 0x000000ffu) + ".";
            s += std::to_string(addr >> 16u & 0x000000ffu) + ".";
            s += std::to_string(addr >> 8u & 0x000000ffu) + ".";
            s += std::to_string(addr >> 0u & 0x000000ffu);
            return s;
        }

        //! converts an IPv4 address in dotted-decimal notation to a 4 Byte unsigned integer
        //! - only performs rudimentary format checking
        static std::uint32_t str_to_addr(const std::string &s) {
            unsigned char a[4] = {0};

            int bytes = std::sscanf(s.c_str(), "%hhd.%hhd.%hhd.%hhd", a + 0, a + 1, a + 2, a + 3);

            if (bytes < 4)
                throw std::invalid_argument("invalid ip address");

            return (uint32_t) (a[0]) << 24u | (uint32_t) (a[1]) << 16u |
                   (uint32_t) (a[2]) << 8u | (uint32_t) (a[3]);
        }
    }

    namespace udp {

        const unsigned HDR_LEN = 8;

        struct hdr { // 8
            std::uint16_t src_port    = 0; // 2
            std::uint16_t dst_port    = 0; // 2
            std::uint16_t dgram_len   = 0; // 2
            std::uint16_t dgram_cksum = 0; // 2 // 8
        };
    }

    struct tcp_or_udp_hdr { // 4
        std::uint16_t src_port  = 0; // 2
        std::uint16_t dst_port  = 0; // 2
    };

    struct ipv4_5tuple {

        //! returns an ipv4_5tuple struct from raw packet buffer
        //! - reverses the byte order of the ip_src, ip_dst, tp_src, tp_dst fields
        //! - leaves tp_src = 0, tp_dst = 0 if the transport layer protocol is
        //!   neither TCP or UDP
        static ipv4_5tuple from_ipv4_pkt_data(const unsigned char* pkt_data);

        ipv4_5tuple() = default;
        ipv4_5tuple(std::uint32_t ip_src, std::uint32_t ip_dst, std::uint16_t tp_src,
                             std::uint16_t tp_dst, std::uint8_t ip_proto)
            : ip_src(ip_src), ip_dst(ip_dst), tp_src(tp_src), tp_dst(tp_dst), ip_proto(ip_proto) { }

        ipv4_5tuple(const ipv4_5tuple&) = default;
        ipv4_5tuple& operator=(const ipv4_5tuple&) = default;

        std::uint32_t ip_src   = 0;
        std::uint32_t ip_dst   = 0;
        std::uint16_t tp_src   = 0;
        std::uint16_t tp_dst   = 0;
        std::uint8_t  ip_proto = 0;

        inline bool operator==(const ipv4_5tuple& other) const {
            return std::tie(ip_src, ip_dst, tp_src, tp_dst, ip_proto)
                   == std::tie(other.ip_src, other.ip_dst, other.tp_src, other.tp_dst, other.ip_proto);
        }

        inline bool operator!=(const ipv4_5tuple& other) const {
            return !(*this == other);
        }

        inline bool operator<(const ipv4_5tuple& other) const {
            return std::tie(ip_src, ip_dst, tp_src, tp_dst, ip_proto)
                   < std::tie(other.ip_src, other.ip_dst, other.tp_src, other.tp_dst, other.ip_proto);
        }
    };

    struct ipv4_port {
        std::uint32_t ip   = 0;
        std::uint16_t port = 0;

        inline bool operator<(const ipv4_port& other) const {
            return std::tie(ip, port) < std::tie(other.ip, other.port);
        }

        inline bool operator==(const ipv4_port& other) const {
            return std::tie(ip, port) == std::tie(other.ip, other.port);
        }
    };

    struct ipv4_mask {
        std::uint32_t ip   = 0;
        std::uint32_t mask = 0;

        inline bool match(const std::uint32_t test_ip) const {
            return (test_ip & mask) == (ip & mask);
        }

        inline bool operator<(const ipv4_mask& other) const {
            return std::tie(ip, mask) < std::tie(other.ip, other.mask);
        }

        inline bool operator==(const ipv4_mask& other) const {
            return std::tie(ip, mask) == std::tie(other.ip, other.mask);
        }
    };
}

static std::ostream& operator<<(std::ostream& os, const net::ipv4_5tuple& ip_5t) {
    return os << (unsigned) ip_5t.ip_proto << "," << net::ipv4::addr_to_str(ip_5t.ip_src) << ","
              << ip_5t.tp_src << "," << net::ipv4::addr_to_str(ip_5t.ip_dst) << "," << ip_5t.tp_dst;
}

namespace std {
    template<> struct hash<net::ipv4_5tuple> {
        //! computes a rudimentary std::size_t-length hash over a ipv4_5tuple
        //! - for use with STL containers, such as std::unordered_map
        std::size_t operator()(const net::ipv4_5tuple& d) const noexcept {
            std::size_t a = 0, b = 0;
            // pack into two different long unsigned integers
            a |= (std::size_t) d.ip_src   << 32u;
            a |= (std::size_t) d.ip_dst   <<  0u;
            b |= (std::size_t) d.tp_src   << 24u;
            b |= (std::size_t) d.tp_dst   <<  8u;
            b |= (std::size_t) d.ip_proto <<  0u;
            return a ^ (b + 0x9e3779b9 + (a << 6u) + (a >> 2u));
        }
    };

    template<> struct hash<net::ipv4_port> {
        std::size_t operator()(const net::ipv4_port& d) const noexcept  {
            std::size_t h = 0;
            h |= (std::size_t) d.ip  << 16u;
            h |= (std::size_t) d.port << 0u;
            return h;
        }
    };
}

#endif
