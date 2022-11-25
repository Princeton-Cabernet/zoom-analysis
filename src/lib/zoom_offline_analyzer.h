#ifndef ZOOM_ANALYSIS_ZOOM_OFFLINE_ANALYZER_H
#define ZOOM_ANALYSIS_ZOOM_OFFLINE_ANALYZER_H

#include <map>

#include "rtp_stream_analyzer.h"
#include "zoom.h"
#include "zoom_analyzer.h"

namespace zoom {

    class offline_analyzer : public analyzer {

    static const unsigned STREAM_ANALYZER_BUF_LEN = 64;

    using stream_analyzer = rtp_stream_analyzer<zoom::media_stream_key,
        zoom::rtp_pkt_meta, STREAM_ANALYZER_BUF_LEN>;

    struct stream_data {
        stream_analyzer analyzer;
    };

    using media_streams_map = std::map<zoom::media_stream_key, stream_data>;

    public:

        offline_analyzer() = default;
        offline_analyzer(offline_analyzer&&) = default;
        offline_analyzer& operator=(offline_analyzer&&) = default;

        void add(const zoom::pkt& pkt);
        void write_streams_log();

    private:

        media_streams_map::iterator _insert_new_stream(const zoom::media_stream_key& key,
                                                       const zoom::pkt& pkt);

        void _frame_handler(const stream_analyzer& a, const struct stream_analyzer::frame& f);
        void _stats_handler(const stream_analyzer& a, unsigned report_count,
                            unsigned ts, const struct stream_analyzer::stats& c);

        void _write_pkt_log(const zoom::pkt& pkt);
        void _write_frame_log(const stream_analyzer& a, const struct stream_analyzer::frame& frame);
        void _write_stats_log(const zoom::media_stream_key& k, unsigned report_count, unsigned ts,
                              const struct stream_analyzer::stats& c);

        unsigned long _pkts_processed = 0;
        media_streams_map _media_streams;
    };
}

#endif
