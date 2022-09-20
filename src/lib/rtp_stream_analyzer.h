#ifndef ZOOM_ANALYSIS_RTP_STREAM_ANALYZER_H
#define ZOOM_ANALYSIS_RTP_STREAM_ANALYZER_H

#include <cstdint>
#include <functional>

#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cassert>

#include "fps_calculator.h"
#include "jitter_calculator.h"
#include "pcap_util.h"

struct rtp_stream_analyzer_empty_meta { };

template <
    typename StreamMeta = rtp_stream_analyzer_empty_meta,
    typename PacketMeta = rtp_stream_analyzer_empty_meta,
    unsigned Len = 32>
class rtp_stream_analyzer {

public:

    struct pkt {
        bool empty            = true;
        bool seen             = false;
        std::uint16_t rtp_seq = 0;
        std::uint32_t rtp_ts  = 0;
        timeval ts            = { 0, 0 };
        unsigned pl_len       = 0;
        PacketMeta meta       = {};
    };

    struct frame {
        std::uint32_t rtp_ts  = 0;
        unsigned pkts_seen    = 0;
        timeval ts_min        = {0, 0};
        timeval ts_max        = {0, 0};
        unsigned total_pl_len = 0;
        unsigned fps          = 0;
        double jitter         = 0.0;
        struct pkt pkts[Len]  = {};
    };

    struct stats {
        unsigned long total_pkts        = 0;
        unsigned long total_bytes       = 0;
        unsigned long out_of_order_pkts = 0;
        unsigned long duplicate_pkts    = 0;
        unsigned long lost_pkts         = 0;
        unsigned long total_frames      = 0;

        unsigned long frame_size_sum = 0;
        double jitter_sum = 0.0;

        [[nodiscard]] inline double mean_frame_size() const {
            return total_frames ? (frame_size_sum / (double) total_frames) : -1;
        }

        [[nodiscard]] inline double mean_jitter() const {
            return total_frames ? (jitter_sum / (double) total_frames) : -1;
        }

        struct stats operator-(const struct stats& other) {

            if (total_pkts < other.total_pkts
                || total_bytes < other.total_bytes
                || out_of_order_pkts < other.out_of_order_pkts
                || duplicate_pkts < other.duplicate_pkts
                || lost_pkts < other.lost_pkts
                || total_frames < other.total_frames) {

                throw std::logic_error("subtrahend must be larger than minuend");
            }

            return stats {
                .total_pkts        = total_pkts - other.total_pkts,
                .total_bytes       = total_bytes - other.total_bytes,
                .out_of_order_pkts = out_of_order_pkts - other.out_of_order_pkts,
                .duplicate_pkts    = duplicate_pkts - other.duplicate_pkts,
                .lost_pkts         = lost_pkts - other.lost_pkts,
                .total_frames      = total_frames - other.total_frames,
            };
        }
    };

    using FrameHandlerFx = std::function<void (const rtp_stream_analyzer& a, const frame&)>;
    using StatsHandlerFx = std::function<void (const rtp_stream_analyzer& a, unsigned report_count,
                                               unsigned ts, const stats&)>;

    rtp_stream_analyzer() = delete;

    explicit rtp_stream_analyzer(
            FrameHandlerFx&& frame_handler,
            StatsHandlerFx&& stats_handler,
            unsigned sampling_rate_khz = 90000,
            const StreamMeta& meta = {})
        : _frame_handler(std::move(frame_handler)),
          _stats_handler(std::move(stats_handler)),
          _meta(meta),
          _fps_calc(512),
          _jitter_calc(sampling_rate_khz) {

        static_assert(Len >= 8 && _is_power_of_two(Len));
    }

    rtp_stream_analyzer(const rtp_stream_analyzer&)                = default;
    rtp_stream_analyzer& operator=(const rtp_stream_analyzer&)     = default;
    rtp_stream_analyzer(rtp_stream_analyzer&&) noexcept            = default;
    rtp_stream_analyzer& operator=(rtp_stream_analyzer&&) noexcept = default;

    void add(std::uint16_t rtp_seq, std::uint32_t rtp_ts, const timeval& ts, unsigned pl_len,
             const PacketMeta& meta) {

        if (_counters.total_pkts == 0) { // initial entry
            _ring[0] = {
                .empty = false, .seen = true, .rtp_seq = rtp_seq, .rtp_ts = rtp_ts, .ts = ts,
                .pl_len = pl_len
            };

            _current_ts_s = ts.tv_sec;

        } else {

            auto head_seq = _ring[_head].rtp_seq;

            if (rtp_seq > head_seq) { // seq # larger than highest seen seq #

                unsigned seq_diff = rtp_seq - head_seq;

                for (unsigned i = 1; i <= seq_diff; i++) {

                    unsigned idx = _idx(_head + i);

                    if (i < seq_diff) {
                        // fill in sequence numbers but set seen = false for skipped packets
                        _set(idx, head_seq + i, 0, {0, 0}, pl_len, false, meta);
                    } else { // seen (last) sequence number
                        _set(idx, rtp_seq, rtp_ts, ts, pl_len, true, meta);
                    }
                }

                _head = _idx(_head + seq_diff);

            } else if (rtp_seq <= head_seq) { // seq # smaller or equal highest seen seq #

                unsigned seq_diff = head_seq - rtp_seq;

                if (seq_diff >= 0 && rtp_seq > 0) {

                    if (seq_diff > 0)
                        _counters.out_of_order_pkts++, _current_ts_counters.out_of_order_pkts++;

                    unsigned idx = _idx(_head - seq_diff);
                    _set(idx, rtp_seq, rtp_ts, ts, pl_len, true, meta);

                } else if (seq_diff > Len) { // handle overflow

                    unsigned idx = _idx(_head + 1);
                    _set(idx, rtp_seq, rtp_ts, ts, pl_len, true, meta);
                    _head = idx;
                }
            }

            if (ts.tv_sec > _current_ts_s) {
                _stats_handler(*this, _stats_report_count++, _current_ts_s, _current_ts_counters);

                _current_ts_counters = {};
                _current_ts_s = ts.tv_sec;
            }

        }

        _counters.total_pkts += 1, _current_ts_counters.total_pkts += 1;
        _counters.total_bytes += pl_len, _current_ts_counters.total_bytes += pl_len;
    }

    const struct stats& stats() const {
        return _counters;
    }

    void flush() {

        for (unsigned i = 0; i < Len;) {
            unsigned idx = _idx(_head+i+1);

            if (_ring[idx].empty) {
                i++;
            } else {
                unsigned j = 0;
                struct frame evict_frame{};
                evict_frame.rtp_ts = _ring[idx].rtp_ts;
                evict_frame.ts_min = _ring[idx].ts;
                evict_frame.ts_max = _ring[idx].ts;

                for (; j < Len && (_ring[_idx(idx+j)].rtp_ts == _ring[idx].rtp_ts
                        || (_ring[_idx(idx+j)].rtp_ts == 0 && !_ring[_idx(idx+j)].empty)); j++) {

                    if (_ring[_idx(idx+j)].rtp_ts != 0) {
                        evict_frame.pkts[evict_frame.pkts_seen++] = _ring[_idx(idx + j)];
                        evict_frame.total_pl_len += _ring[_idx(idx + j)].pl_len;

                        evict_frame.ts_min = _ring[_idx(idx + j)].ts < evict_frame.ts_min ?
                                             _ring[_idx(idx + j)].ts : evict_frame.ts_min;

                        evict_frame.ts_max = _ring[_idx(idx + j)].ts > evict_frame.ts_max ?
                                             _ring[_idx(idx + j)].ts : evict_frame.ts_max;
                    }

                    if (!_ring[_idx(idx+j)].empty && !_ring[_idx(idx+j)].seen) {
                        _counters.lost_pkts += 1, _current_ts_counters.lost_pkts += 1;
                    }
                }

                if (evict_frame.pkts_seen > 0) {
                    _evict_frame(evict_frame);
                }

                i += j;
            }
        }
    }

    void reset() {

        for (unsigned i = 0; i < Len; i++) {
            _ring[i] = { };
        }

        _head = 0, _counters = {}, _current_ts_counters = {};
    }

    inline const StreamMeta& meta() const {
        return _meta;
    }

    virtual ~rtp_stream_analyzer() = default;

    /*
    std::string _debug_string() const {
        std::stringstream ss;
        for (auto i = 0; i < Len; i++) {
            ss << "[" << (i == (_head % Len) ? "H" : "-") << "," << (_ring[i].empty ? "E" : "-")
                << "," << (_ring[i].seen ? "S" : "-") << "," << _ring[i].rtp_seq << ","
                << _ring[i].rtp_ts << "]";
        }
        return ss.str();
    }
    */

private:

    inline static bool constexpr _is_power_of_two(const unsigned x) {
        return (x != 0) && ((x & (x - 1)) == 0);
    }

    [[nodiscard]] inline unsigned _idx(unsigned i) const {
        return i & (Len - 1); // == i % _size (for powers of 2)
    }

    void _set(unsigned idx, std::uint16_t rtp_seq, std::uint32_t rtp_ts, const timeval& ts,
              unsigned pl_len, bool seen, const PacketMeta& meta) {

        if (_ring[idx].seen && _ring[idx].rtp_seq == rtp_seq) {
            _counters.duplicate_pkts += 1, _current_ts_counters.duplicate_pkts += 1;
        }

        if (!_ring[idx].empty && _ring[idx].seen && _ring[idx].rtp_seq != rtp_seq) {

            struct frame evict_frame{};
            evict_frame.rtp_ts = _ring[idx].rtp_ts;
            evict_frame.ts_min = _ring[idx].ts;
            evict_frame.ts_max = _ring[idx].ts;

            for (unsigned i = idx, j = 0; j < Len && ((!_ring[i].empty && _ring[i].rtp_ts == 0)
                    || _ring[i].rtp_ts == _ring[idx].rtp_ts); i = _idx(i + 1), j++) {

                if (!_ring[i].empty && !_ring[i].seen) {
                    _counters.lost_pkts += 1, _current_ts_counters.lost_pkts += 1;
                }

                _ring[i].seen = false, _ring[i].empty = true;

                if (_ring[i].rtp_ts == _ring[idx].rtp_ts) {
                    evict_frame.pkts[evict_frame.pkts_seen++] = _ring[i];
                    evict_frame.total_pl_len += _ring[i].pl_len;

                    evict_frame.ts_min = _ring[i].ts < evict_frame.ts_min ?
                            _ring[i].ts : evict_frame.ts_min;

                    evict_frame.ts_max = _ring[i].ts > evict_frame.ts_max ?
                                         _ring[i].ts : evict_frame.ts_max;
                }
            }

            if (evict_frame.pkts_seen > 0) {
                _evict_frame(evict_frame);
            }
        }

        assert(idx >= 0 && idx < Len);

        _ring[idx] = { .empty = false, .seen = seen, .rtp_seq = rtp_seq, .rtp_ts = rtp_ts, .ts = ts,
                       .pl_len = pl_len, .meta = meta };
    }

    void _evict_frame(frame& f) {
        f.fps = _fps_calc.add_frame(f.ts_max);
        f.jitter = _jitter_calc.add_frame(f.ts_max, f.rtp_ts);
        _counters.total_frames += 1, _current_ts_counters.total_frames += 1;

        _current_ts_counters.frame_size_sum += f.total_pl_len;
        _current_ts_counters.jitter_sum += f.jitter;

        _frame_handler(*this, f);
    }

    unsigned _head             = 0;
    struct stats _counters  = {};
    std::array<pkt, Len> _ring = {};
    FrameHandlerFx _frame_handler;
    StatsHandlerFx _stats_handler;
    StreamMeta _meta;
    fps_calculator _fps_calc;
    jitter_calculator _jitter_calc;
    unsigned _current_ts_s = 0;
    unsigned _stats_report_count = 0;
    struct stats _current_ts_counters = {};
};

#endif
