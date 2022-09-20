
#ifndef ZOOM_ANALYSIS_ZOOM_OFFLINE_ANALYZER_H
#define ZOOM_ANALYSIS_ZOOM_OFFLINE_ANALYZER_H

#include "rtp_stream_analyzer.h"
#include "zoom.h"
#include "zoom_analyzer.h"
#include "zoom_rtp_stream_tracker.h"

namespace zoom {
    class offline_analyzer : public analyzer {

    static const unsigned STREAM_ANALYZER_BUF_LEN = 64;

    using stream_analyzer = rtp_stream_analyzer<zoom::rtp_stream_meta,
        zoom::rtp_pkt_meta, STREAM_ANALYZER_BUF_LEN>;

    struct stream_state {
        stream_analyzer analyzer;
    };

    public:
        offline_analyzer() = default;
        offline_analyzer(offline_analyzer&&) = default;
        offline_analyzer& operator=(offline_analyzer&&) = default;

        void add(const zoom::pkt& pkt);

        void write_streams_log();

    private:
        void _write_pkt_log(const zoom::pkt& pkt);
        void _write_frame_log(const stream_analyzer& a, const struct stream_analyzer::frame& frame);
        void _write_stats_log(const zoom::rtp_stream_meta& m, unsigned report_count, unsigned ts,
                              const struct stream_analyzer::stats& c);

//        bool _has_stream(const zoom::rtp_stream_key& key) const;
//        stream_state& _get_stream(const zoom::rtp_stream_key& key);
//        stream_state& _init_stream(const zoom::rtp_stream_key& key);

        unsigned long _pkts_processed = 0;

        zoom::rtp_stream_tracker _rtp_stream_tracker;
        zoom::rtp_stream_tracker rtp_stream_tracker;
        std::map<zoom::rtp_stream_key, stream_state> streams;
    };
}

#endif
