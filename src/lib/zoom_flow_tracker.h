
#ifndef ZOOM_ANALYSIS_ZOOM_FLOW_TRACKER_H
#define ZOOM_ANALYSIS_ZOOM_FLOW_TRACKER_H

#include "net.h"

#include <ctime>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace zoom {

    class flow_tracker {

    public:

        enum class flow_type : unsigned {
            unknown  = 0,
            tcp      = 1,
            udp_srv  = 2,
            udp_stun = 3,
            udp_p2p  = 4
        };

        struct flow_stats {
            unsigned id = 0;
            unsigned long pkts = 0, bytes = 0;
            timeval start_ts = { 0, 0 }, last_ts = { 0, 0 };
            flow_type type = flow_type::unknown;

            [[nodiscard]] bool is_udp() const;
            [[nodiscard]] bool is_stun() const;
            [[nodiscard]] bool is_tcp() const;
            [[nodiscard]] bool is_p2p() const;
        };

        static std::string flow_type_string(const flow_type& ft) {
            switch (ft) {
                case flow_type::tcp:      return "tcp";
                case flow_type::udp_srv:  return "udp_srv";
                case flow_type::udp_stun: return "udp_stun";
                case flow_type::udp_p2p:  return "udp_p2p";
                default:                  return "unknown";
            }
        }

        explicit flow_tracker(unsigned stun_expiration = 300);

        flow_tracker(const flow_tracker&) = default;
        flow_tracker& operator=(const flow_tracker&) = default;

        std::optional<flow_stats> track(const net::ipv4_5tuple& ip_5t, const timeval& ts,
                                        unsigned bytes);

        unsigned count_zoom_flows_detected() const;
        unsigned long long count_total_pkts_processed() const;
        unsigned long long count_zoom_pkts_detected() const;
        unsigned long long count_zoom_bytes_detected() const;

        const std::unordered_map<net::ipv4_5tuple, flow_stats>& flows() const;

    private:

        inline static bool _is_tcp(const net::ipv4_5tuple& ip_5t) {
            return ip_5t.ip_proto == 6;
        }

        inline static bool _is_udp(const net::ipv4_5tuple& ip_5t) {
            return ip_5t.ip_proto == 17;
        }

        inline static bool _is_stun_port(uint16_t p) {
            return p == 3478 || p == 3479;
        }

        unsigned _next_id = 0;
        unsigned _stun_expiration = 300;
        std::unordered_map<net::ipv4_5tuple, flow_stats> _flows = {};
        std::unordered_map<net::ipv4_port, long> _p2p_peers = {};
        unsigned long long _total_pkts_processed = 0;
        unsigned long long _zoom_pkts_detected = 0;
        unsigned long long _zoom_bytes_detected = 0;
    };
}

#endif
