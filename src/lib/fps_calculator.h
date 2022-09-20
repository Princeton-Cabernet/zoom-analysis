#ifndef ZOOM_ANALYSIS_FPS_CALCULATOR_H
#define ZOOM_ANALYSIS_FPS_CALCULATOR_H

#include <cstddef>
#include <cstdlib>

#include "ring_buffer.h"

class fps_calculator {

public:

    fps_calculator(const fps_calculator& copy_from) = default;
    fps_calculator& operator=(const fps_calculator& copy_from) = default;

    explicit fps_calculator(std::size_t ring_len = 64);
    [[nodiscard]] unsigned add_frame(const timeval& ts);

    virtual ~fps_calculator() = default;

private:
    ring_buffer<timeval> _frames;
};

#endif
