
#include <arpa/inet.h>
#include <iostream>
#include "zoom_rtp_stream_tracker.h"

bool zoom::rtp_stream_tracker::stream_key::operator<(const struct stream_key& a) const {
    return std::tie(rtp_ssrc, rtp_pl_type, ip_src, ip_dst)
           < std::tie(a.rtp_ssrc, a.rtp_pl_type, a.ip_src, a.ip_dst);
}

bool zoom::rtp_stream_tracker::stream_key::operator==(const struct stream_key& a) const {
    return std::tie(rtp_ssrc, rtp_pl_type, ip_src, ip_dst)
           == std::tie(a.rtp_ssrc, a.rtp_pl_type, a.ip_src, a.ip_dst);
}

zoom::rtp_stream_tracker::stream_data zoom::rtp_stream_tracker::track(const zoom::pkt& pkt) {

    stream_key key {
        .rtp_ssrc    = pkt.proto.rtp.ssrc,
        .rtp_pl_type = pkt.proto.rtp.pt,
        .ip_src      = pkt.ip_5t.ip_src,
        .ip_dst      = pkt.ip_5t.ip_dst
    };

    auto flow_type = zoom::flow_tracker::flow_type::unknown;

    if (pkt.flags.srv)
        flow_type = zoom::flow_tracker::flow_type::udp_srv;

    if (pkt.flags.p2p)
        flow_type = zoom::flow_tracker::flow_type::udp_p2p;

    auto streams_it = _streams.find(key);

    if (streams_it != _streams.end()) {

        auto& data = streams_it->second;
        // check whether new flow should be started will go here

        if (data.flows.back().ip_5t != pkt.ip_5t) {

            flow new_flow{
                    .type         = flow_type,
                    .ip_5t        = pkt.ip_5t,
                    .pkts         = 1,
                    .bytes        = pkt.udp_pl_len,
                    .start_ts     = timeval{.tv_sec = pkt.ts.s, .tv_usec = (int) pkt.ts.us},
                    .last_ts      = timeval{.tv_sec = pkt.ts.s, .tv_usec = (int) pkt.ts.us},
                    .start_rtp_ts = pkt.proto.rtp.ts,
                    .last_rtp_ts  = pkt.proto.rtp.ts
            };

            data.flows.push_back(new_flow);

        } else {
            data.flows.back().pkts++;
            data.flows.back().bytes += pkt.udp_pl_len;
            data.flows.back().last_ts = timeval{.tv_sec = pkt.ts.s, .tv_usec = (int) pkt.ts.us};
            data.flows.back().last_rtp_ts = pkt.proto.rtp.ts;
        }

        return data;

    } else {

        flow first_flow{
                .type         = flow_type,
                .ip_5t        = pkt.ip_5t,
                .pkts         = 1,
                .bytes        = pkt.udp_pl_len,
                .start_ts     = timeval{.tv_sec = pkt.ts.s, .tv_usec = (int) pkt.ts.us},
                .last_ts      = timeval{.tv_sec = pkt.ts.s, .tv_usec = (int) pkt.ts.us},
                .start_rtp_ts = pkt.proto.rtp.ts,
                .last_rtp_ts  = pkt.proto.rtp.ts
        };

        stream_data data{
            // .session_id = _session_id(key, flow_type, ts),
            .zoom_type = pkt.zoom_media_type,
            .flows = { first_flow }
        };

        // std::cout << key.rtp_ssrc << "," << data.session_id << std::endl;

        auto const& [it, success] = _streams.insert({key, data});

        if (!success)
            throw std::runtime_error("rtp_stream_tracker::track: could not insert entry");

        return data;
    }
}

zoom::rtp_stream_tracker::stream_data zoom::rtp_stream_tracker::track(const timeval& ts,
    const net::ipv4_5tuple& ip_5t, zoom::flow_tracker::flow_type flow_type, unsigned zoom_type,
    unsigned udp_pl_len, const rtp::hdr* rtp_hdr) {

    stream_key key {
        .rtp_ssrc = ntohl(rtp_hdr->ssrc), .rtp_pl_type = rtp_hdr->payload_type(),
        .ip_src = ip_5t.ip_src, .ip_dst = ip_5t.ip_dst
    };

    auto streams_it = _streams.find(key);

    if (streams_it != _streams.end()) {

        auto& data = streams_it->second;
        // check whether new flow should be started will go here

        if (data.flows.back().ip_5t != ip_5t) {

            flow new_flow{
                .type         = flow_type,
                .ip_5t        = ip_5t,
                .pkts         = 1,
                .bytes        = udp_pl_len,
                .start_ts     = ts,
                .last_ts      = ts,
                .start_rtp_ts = ntohl(rtp_hdr->ts),
                .last_rtp_ts  = ntohl(rtp_hdr->ts)
            };

            data.flows.push_back(new_flow);

        } else {
            data.flows.back().pkts++;
            data.flows.back().bytes += udp_pl_len;
            data.flows.back().last_ts = ts;
            data.flows.back().last_rtp_ts = ntohl(rtp_hdr->ts);
        }

        return data;

    } else {

        flow first_flow{
            .type         = flow_type,
            .ip_5t        = ip_5t,
            .pkts         = 1,
            .bytes        = udp_pl_len,
            .start_ts     = ts,
            .last_ts      = ts,
            .start_rtp_ts = ntohl(rtp_hdr->ts),
            .last_rtp_ts  = ntohl(rtp_hdr->ts)
        };

        stream_data data{
            // .session_id = _session_id(key, flow_type, ts),
            .zoom_type = zoom_type,
            .flows = { first_flow }
        };

        // std::cout << key.rtp_ssrc << "," << data.session_id << std::endl;

        auto const& [it, success] = _streams.insert({key, data});

        if (!success)
            throw std::runtime_error("rtp_stream_tracker::track: could not insert entry");

        return data;
    }
}
