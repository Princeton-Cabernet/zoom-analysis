#ifndef ZOOM_ANALYSIS_JITTER_CALCULATOR_H
#define ZOOM_ANALYSIS_JITTER_CALCULATOR_H

#include <cstdint>
#include <cstdlib>

class jitter_calculator {

public:

    explicit jitter_calculator(unsigned sampling_rate = 90000);

    //! returns RTP jitter in milliseconds
    [[nodiscard]] double add_frame(const timeval& ts, std::uint32_t rtp_ts);

    //! converts a RTP timestamp to wallclock time in milliseconds
    static inline unsigned long long rtp_ts_to_wallclock_ms(std::uint32_t rtp_ts,
                                                            unsigned sampling_rate_khz) {
        return (unsigned long long) ((double) rtp_ts / (double) sampling_rate_khz * 1000);
    }

    //! converts a timeval to milliseconds
    static inline unsigned long long timeval_to_ms(timeval tv) {
        return (unsigned long long) (((double) tv.tv_sec * 1000.0) + (tv.tv_usec / 1000.0));
    }

private:

    unsigned _i = 0; // frame number
    unsigned _sampling_rate = 90000;
    unsigned long long _r = 0; // arrival time
    unsigned long long _s = 0; // rtp timestamp

    long long _d = 0;
    long double _j = 0.0;
};

#endif
