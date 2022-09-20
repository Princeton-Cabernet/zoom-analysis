
#ifndef ZOOM_ANALYSIS_ZOOM_ANALYZER_H
#define ZOOM_ANALYSIS_ZOOM_ANALYZER_H

#include <string>
#include <fstream>

namespace zoom {
    class analyzer {
    public:
        analyzer() = default;
        analyzer(const analyzer&) = delete;
        analyzer& operator=(const analyzer&) = delete;
        analyzer(analyzer&&) = default;
        analyzer& operator=(analyzer&&) = default;

        void enable_pkt_log(const std::string& file_path);
        void enable_frame_log(const std::string& file_path);
        void enable_streams_log(const std::string& file_path);
        void enable_stats_log(const std::string& stats_path);

    protected:

        struct _log {
            void open(const std::string& file_path);
            bool enabled = false;
            std::ofstream stream;
            void close();
        };

        _log _pkt_log;
        _log _frame_log;
        _log _streams_log;
        _log _stats_log;
    };
}

#endif
