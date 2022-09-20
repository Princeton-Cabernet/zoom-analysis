
#include "fps_calculator.h"

#include <stdexcept>
#include "pcap_util.h"

fps_calculator::fps_calculator(std::size_t ring_len)
    : _frames(ring_len) { }

unsigned fps_calculator::add_frame(const timeval& ts) {

    if (!_frames.push(ts)) {
        throw std::runtime_error("too many frames");
    }

    while (!_frames.empty() && (ts - _frames.peek()) >= timeval{1, 0}) {
        _frames.pop();
    }

    return _frames.count();
}
