
#include "zoom_offline_analyzer.h"

void zoom::offline_analyzer::add(const zoom::pkt& pkt) {

    _pkts_processed++;

    if (_pkt_log.enabled) {
        _write_pkt_log(pkt);
    }

    if (pkt.flags.rtp) {

        auto stream_data = _rtp_stream_tracker.track(pkt);
        auto stream_key = zoom::rtp_stream_key::from_pkt(pkt);
        auto streams_it = streams.find(stream_key);

        if (streams_it == streams.end()) {

            auto stream_meta = zoom::rtp_stream_meta::from_pkt(pkt);

            auto frame_handler = [this](const stream_analyzer& a,
                const struct stream_analyzer::frame& f) -> void {

                if (_frame_log.enabled)
                    _write_frame_log(a, f);
            };

            auto stats_handler = [this](const stream_analyzer& a, unsigned report_count,
                    unsigned ts, const struct stream_analyzer::stats& c) -> void {

                if (_stats_log.enabled)
                    _write_stats_log(a.meta(), report_count, ts, c);
            };

            // use 8,000 kHz for audio, 90,000 kHz for video
            auto sampling_rate = pkt.zoom_media_type == 15 ? 8000 : 90000;
            stream_analyzer a(frame_handler, stats_handler, sampling_rate, stream_meta);

            const auto &[it, success]
                    = streams.emplace(stream_key, stream_state{.analyzer = std::move(a)});

            if (success) {
                streams_it = it;
            } else {
                std::cerr << "error: failed setting up stream state, exiting." << std::endl;
                return;
            }
        }

        timeval tv{pkt.ts.s, (int) pkt.ts.us};

        streams_it->second.analyzer.add(
            pkt.proto.rtp.seq, pkt.proto.rtp.ts, tv, pkt.udp_pl_len, {
                .rtp_ext1 = { pkt.rtp_ext1[0], pkt.rtp_ext1[1], pkt.rtp_ext1[2] },
                .pkt_type = pkt.zoom_media_type,
                .pkts_hint = pkt.pkts_in_frame
        });
    }
}

void zoom::offline_analyzer::write_streams_log() {

    _streams_log.stream << "# ssrc,pl_type,ip_src,tp_src,ip_dst,tp_dst,flow_type,zoom_type,start_ts_s,"
                << "start_ts_us,end_ts_s,end_ts_us,start_rtp_ts,last_rtp_ts,pkts,bytes" << std::endl;

    for (const auto& [key, data]: _rtp_stream_tracker.streams()) {
        for (const auto& flow: data.flows) {
            _streams_log.stream
                << key.rtp_ssrc << ","
                << key.rtp_pl_type << ","
                << net::ipv4::addr_to_str(flow.ip_5t.ip_src) << ","
                << flow.ip_5t.tp_src << ","
                << net::ipv4::addr_to_str(flow.ip_5t.ip_dst) << ","
                << flow.ip_5t.tp_dst << ","
                << zoom::flow_tracker::flow_type_string(flow.type) << ","
                << data.zoom_type << ","
                << flow.start_ts.tv_sec << ","
                << flow.start_ts.tv_usec << ","
                << flow.last_ts.tv_sec << ","
                << flow.last_ts.tv_usec << ","
                << std::dec << flow.start_rtp_ts << ","
                << std::dec << flow.last_rtp_ts << ","
                << flow.pkts << ","
                << flow.bytes << std::endl;
        }
    }
}

void zoom::offline_analyzer::_write_pkt_log(const zoom::pkt& pkt) {

    _pkt_log.stream << std::dec<< pkt.ts.s << "," << pkt.ts.us << ",u,";

    if (pkt.flags.srv) {
        _pkt_log.stream << "s,";
    } else if (pkt.flags.p2p) {
        _pkt_log.stream << "p,";
    } else {
        _pkt_log.stream << "NA,";
    }

    _pkt_log.stream << pkt.ip_5t << ",";

    //TODO: handle screen share
    if (pkt.zoom_media_type == zoom::AUDIO_TYPE) {
        _pkt_log.stream << "a,";
    } else if (pkt.zoom_media_type == zoom::VIDEO_TYPE) {
        _pkt_log.stream << "v,";
    } else {
        _pkt_log.stream << "NA,";
    }

    if (pkt.pkts_in_frame) {
        _pkt_log.stream << pkt.pkts_in_frame << ",";
    } else {
        _pkt_log.stream << "NA,";
    }

    _pkt_log.stream
        << std::dec << (unsigned) pkt.proto.rtp.ssrc << ","
        << std::dec << (unsigned) pkt.proto.rtp.pt << ","
        << std::dec << (unsigned) pkt.proto.rtp.seq << ","
        << std::dec << (unsigned) pkt.proto.rtp.ts << ","
        << std::dec << (unsigned) pkt.udp_pl_len << ",";

    if (pkt.rtp_ext1[0] != 0 || pkt.rtp_ext1[1] != 0 || pkt.rtp_ext1[2] != 0) {
        _pkt_log.stream << "0x";
        _pkt_log.stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned) pkt.rtp_ext1[0];
        _pkt_log.stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned) pkt.rtp_ext1[1];
        _pkt_log.stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned) pkt.rtp_ext1[2];
        _pkt_log.stream << ",";
    } else {
        _pkt_log.stream << "NA,";
    }

    _pkt_log.stream << "0" << std::endl;

}

void zoom::offline_analyzer::_write_frame_log(const stream_analyzer& a, const stream_analyzer::frame& f) {

    auto meta = a.meta();
    const auto* first_pkt = &(f.pkts[0]);

    _frame_log.stream
        << meta.ip_5t << ","
        << std::dec << (unsigned) meta.rtp_ssrc << ","
        << std::dec << (unsigned) meta.rtp_pt << ","
        << std::dec << (unsigned) first_pkt->meta.pkt_type << ","
        << std::hex << std::setw(2) << std::setfill('0')
            << (unsigned) first_pkt->meta.rtp_ext1[0]
        << std::hex << std::setw(2) << std::setfill('0')
            << (unsigned) first_pkt->meta.rtp_ext1[1]
        << std::hex << std::setw(2) << std::setfill('0')
            << (unsigned) first_pkt->meta.rtp_ext1[2] << ","
        << std::dec << (unsigned) f.ts_min.tv_sec << ","
        << std::dec << (unsigned) f.ts_min.tv_usec << ","
        << std::dec << (unsigned) f.ts_max.tv_sec << ","
        << std::dec << (unsigned) f.ts_max.tv_usec << ","
        << std::dec << (unsigned) f.rtp_ts << ","
        << std::dec << (unsigned) f.pkts_seen << ","
        << std::dec << (unsigned) first_pkt->meta.pkts_hint << ","
        << std::dec << (unsigned) f.total_pl_len << ","
        << std::dec << (unsigned) f.fps << ","
        << std::setprecision(5) << f.jitter
        << std::endl;
}

void zoom::offline_analyzer::_write_stats_log(const zoom::rtp_stream_meta& m, unsigned report_count,
                                              unsigned ts,
                                              const struct stream_analyzer::stats& c) {

    _stats_log.stream
        << ts << ","
        << report_count << ","
        << m.ip_5t << ","
        << std::dec << (unsigned) m.media_type << ","
        << m.rtp_ssrc << ","
        << std::dec << (unsigned) m.rtp_pt << ","
        << std::dec << c.total_pkts << ","
        << std::dec << c.total_bytes << ","
        << std::dec << c.lost_pkts << ","
        << std::dec << c.duplicate_pkts << ","
        << std::dec << c.out_of_order_pkts << ","
        << std::dec << c.total_frames << ","
        << std::dec << c.mean_frame_size() << ","
        << std::dec << c.mean_jitter() << std::endl;
}

//bool zoom::offline_analyzer::_has_stream(const zoom::rtp_stream_key& key) const {
//
//    return streams.find(key) != streams.end();
//}
//
//zoom::offline_analyzer::stream_state&
//    zoom::offline_analyzer::_get_stream(const zoom::rtp_stream_key& key) {
//
//    auto it = streams.find(key);
//
//    if (it == streams.end())
//        throw std::logic_error("stream not tracked");
//
//    return it->second;
//}
//
//zoom::offline_analyzer::stream_state&
//    zoom::offline_analyzer::_init_stream(const zoom::rtp_stream_key& key) { }
