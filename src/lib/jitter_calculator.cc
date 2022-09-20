
#include "jitter_calculator.h"

#include <cmath>


jitter_calculator::jitter_calculator(unsigned sampling_rate)
        : _sampling_rate(sampling_rate) { }

double jitter_calculator::add_frame(const timeval& ts, std::uint32_t rtp_ts) {

    if (_i == 0) { // initialization
        _r = timeval_to_ms(ts);
        _s = rtp_ts_to_wallclock_ms(rtp_ts, _sampling_rate);
        _i++;
        return 0.0;
    }

    auto r = timeval_to_ms(ts);
    auto s = rtp_ts_to_wallclock_ms(rtp_ts, _sampling_rate);

    _d = (long long) ((r - _r) - (s - _s));
    _j = _j + (std::abs((long double) _d) - _j) / 16;
    _r = r, _s = s, _i++;

    return (double) _j;
}