
#include "pcap_util.h"
#include "zoom_flow_tracker.h"
#include "zoom_nets.h"

bool zoom::flow_tracker::flow_stats::is_udp() const {
    return type == flow_type::udp_srv || type == flow_type::udp_p2p || type == flow_type::udp_stun;
}

bool zoom::flow_tracker::flow_stats::is_stun() const {
    return type == flow_type::udp_stun;
}

bool zoom::flow_tracker::flow_stats::is_tcp() const {
    return type == flow_type::tcp;
}

bool zoom::flow_tracker::flow_stats::is_p2p() const {
    return type == flow_type::udp_p2p;
}

zoom::flow_tracker::flow_tracker(unsigned int stun_expiration)
    : _stun_expiration(stun_expiration) { }

std::optional<zoom::flow_tracker::flow_stats> zoom::flow_tracker::track(
    const net::ipv4_5tuple& ip_5t, const timeval& ts, unsigned bytes) {

    _total_pkts_processed++;

    auto flows_it = _flows.find(ip_5t);

    if (flows_it != _flows.end()) { // flow has been seen before

        auto& stats = flows_it->second;

        stats.pkts += 1, stats.bytes += bytes;

        if (ts > stats.last_ts)
            stats.last_ts = ts;

        _zoom_pkts_detected++;
        _zoom_bytes_detected += bytes;
        return flows_it->second;

    } else { // flows has not yet been seen

        auto ft = flow_type::unknown;

        if (zoom::nets::match(ip_5t.ip_src) || zoom::nets::match(ip_5t.ip_dst)) {
            // flow is going to / coming from zoom server

            if (_is_udp(ip_5t)) {

                if (_is_stun_port(ip_5t.tp_src) || _is_stun_port(ip_5t.tp_dst)) {

                    net::ipv4_port p2p_local_peer;

                    if (_is_stun_port(ip_5t.tp_src)) {
                        p2p_local_peer = {ip_5t.ip_dst, ip_5t.tp_dst};
                    } else {
                        p2p_local_peer = {ip_5t.ip_src, ip_5t.tp_src};
                    }

                    auto p2p_peers_it = _p2p_peers.find(p2p_local_peer);

                    if (p2p_peers_it == _p2p_peers.end()) {
                        _p2p_peers.insert({p2p_local_peer, ts.tv_sec});
                    } else {
                        p2p_peers_it->second = ts.tv_sec;
                    }

                    ft = flow_type::udp_stun;

                } else {
                    ft = flow_type::udp_srv;
                }

            } else if (_is_tcp(ip_5t)) {
                ft = flow_type::tcp;
            } else {
                return std::nullopt;
            }

        } else { // flow is not going to / coming from zoom server

            if (_is_udp(ip_5t)) {

                auto _p2p_peers_src_it = _p2p_peers.find({ip_5t.ip_src, ip_5t.tp_src});
                auto _p2p_peers_dst_it = _p2p_peers.find({ip_5t.ip_dst, ip_5t.tp_dst});

                if (_p2p_peers_src_it != _p2p_peers.end()
                    && ts.tv_sec <= _p2p_peers_src_it->second + _stun_expiration) {

                    ft = flow_type::udp_p2p;

                } else if (_p2p_peers_dst_it != _p2p_peers.end()
                           && ts.tv_sec <= _p2p_peers_dst_it->second + _stun_expiration) {

                    ft = flow_type::udp_p2p;
                } else {
                    return std::nullopt;
                }
            } else {
                return std::nullopt;
            }
        }

        flow_stats fs{_next_id++, 1, bytes, ts, ts, ft };
        _flows.insert(std::make_pair(ip_5t, fs));
        _zoom_pkts_detected++;
        return fs;
    }
}

unsigned zoom::flow_tracker::count_zoom_flows_detected() const {
    return _next_id;
}

unsigned long long zoom::flow_tracker::count_total_pkts_processed() const {
    return _total_pkts_processed;
}

unsigned long long zoom::flow_tracker::count_zoom_pkts_detected() const {
    return _zoom_pkts_detected;
}

unsigned long long zoom::flow_tracker::count_zoom_bytes_detected() const {
    return _zoom_bytes_detected;
}

const std::unordered_map<net::ipv4_5tuple, zoom::flow_tracker::flow_stats>&
    zoom::flow_tracker::flows() const {

    return _flows;
}
