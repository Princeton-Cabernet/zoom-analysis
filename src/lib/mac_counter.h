#ifndef ZOOM_ANALYSIS_MAC_COUNTER_H
#define ZOOM_ANALYSIS_MAC_COUNTER_H

#include <arpa/inet.h>

#include "net.h"

class mac_counter {
public:

    explicit mac_counter(std::uint32_t wraparound_tolerance = 0xffff);

    mac_counter(const mac_counter&) = default;
    mac_counter& operator=(const mac_counter&) = default;

    void add(const net::eth::addr& a);

    [[nodiscard]] inline std::uint64_t count() const {
        return _total_count + _curr_count;
    }

    [[nodiscard]] inline std::uint32_t wraparound_count() const {
        return _wraparound_count;
    }

    [[nodiscard]] inline std::uint32_t discard_count() const {
        return _discard_count;
    }

private:

    [[nodiscard]] static inline std::uint32_t _eth_addr_to_uint32(const net::eth::addr& a) {
        auto* count = (std::uint32_t*) (a.bytes + 2);
        return ntohl(*count);
    }

    std::uint64_t _curr_count = 0, _total_count = 0;
    std::uint32_t _wraparound_count = 0, _discard_count = 0, _wraparound_tolerance = 0xffff;
};

#endif
