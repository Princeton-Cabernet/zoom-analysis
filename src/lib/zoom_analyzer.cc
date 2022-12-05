#include "zoom_analyzer.h"

void zoom::analyzer::enable_pkt_log(const std::string& file_path) {

    _pkt_log.open(file_path);

    _pkt_log.stream << "#ts_s,ts_us,dir,flow_type,ip_proto,ip_src,tp_src,ip_dst,tp_dst,media_type,"
                    << "pkts_in_frame,ssrc,pt,rtp_seq,rtp_ts,pl_len,rtp_ext1,drop" << std::endl;
}

void zoom::analyzer::enable_frame_log(const std::string& file_path) {

    _frame_log.open(file_path);

    _frame_log.stream << "ip_proto,ip_src,tp_src,ip_dst,tp_dst,ssrc,media_type,rtp_ext1,"
                      << "min_ts_s, min_ts_us,max_ts_s,max_ts_us,rtp_ts,pkts_seen,pkts_hint,"
                      << "frame_size,fps,jitter_ms"
                      << std::endl;
}

void zoom::analyzer::enable_streams_log(const std::string& file_path) {

    _streams_log.open(file_path);
}

void zoom::analyzer::enable_stats_log(const std::string& file_path) {

    _stats_log.open(file_path);

    _stats_log.stream << "ts_s,report_count,rtp_ssrc,media_type,stream_type,ip_src,tp_src,ip_dst,"
                      << "tp_dst,pkts,bytes,lost,duplicate,out_of_order,frames,mean_frame_len,"
                      << "mean_jitter" << std::endl;
}

void zoom::analyzer::_log::open(const std::string& file_path) {

    stream.open(file_path);
    enabled = true;

    if (!stream.is_open())
        throw std::runtime_error("zoom::analyzer: could not open log file at " + file_path);
}

void zoom::analyzer::_log::close() {

    if (!stream.is_open())
        throw std::logic_error("zoom::analyzer: could not close log file: file is not open");

    stream.close();
}
