
#ifndef ZOOM_ANALYSIS_ZOOM_RTP_STREAM_TRACKER_H
#define ZOOM_ANALYSIS_ZOOM_RTP_STREAM_TRACKER_H

#include "net.h"
#include "rtp.h"
#include "zoom.h"
#include "zoom_flow_tracker.h"
#include "zoom_nets.h"

#include <ctime>
#include <map>
#include <vector>
#include <iostream>
#include <cstdlib>

namespace zoom {
    class rtp_stream_tracker {

    public:
        struct stream_key {
            std::uint32_t rtp_ssrc    = 0;
            std::uint32_t rtp_pl_type = 0;
            std::uint32_t ip_src      = 0;
            std::uint32_t ip_dst      = 0;
            bool operator<(const struct stream_key& a) const;
            bool operator==(const struct stream_key& a) const;
        };

        struct flow {
            zoom::flow_tracker::flow_type type;
            net::ipv4_5tuple ip_5t;
            unsigned long pkts = 0, bytes = 0;
            timeval start_ts = { 0, 0 }, last_ts = { 0, 0 };
            unsigned start_rtp_ts = 0, last_rtp_ts = 0;
        };

        struct stream_data {
            unsigned zoom_type = 0;
            std::vector<flow> flows = {};
        };

        rtp_stream_tracker() = default;
        rtp_stream_tracker(const rtp_stream_tracker&) = default;
        rtp_stream_tracker& operator=(const rtp_stream_tracker&) = default;

        stream_data track(const zoom::pkt& pkt);

        stream_data track(const timeval& ts, const net::ipv4_5tuple& ip_5t,
                    zoom::flow_tracker::flow_type flow_type, unsigned zoom_type,
                    unsigned udp_pl_len, const rtp::hdr* rtp_hdr);

        [[nodiscard]] inline const std::map<stream_key, stream_data>& streams() const {
            return _streams;
        }

    private:
        std::map<stream_key, stream_data> _streams = {};
    };
}

#endif
