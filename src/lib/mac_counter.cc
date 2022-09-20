
#include "mac_counter.h"

mac_counter::mac_counter(std::uint32_t wraparound_tolerance)
    : _wraparound_tolerance(wraparound_tolerance) { }

void mac_counter::add(const net::eth::addr& a) {

    auto count_val = _eth_addr_to_uint32(a);

    if (count_val > _curr_count
        && (count_val < _curr_count + _wraparound_tolerance || _curr_count == 0)) {

        _curr_count = count_val;

    } else if ((count_val + _wraparound_tolerance) < _curr_count) {

        _total_count += 0xffffffff;
        _curr_count = count_val;
        _wraparound_count++;

    } else {
        _discard_count++;
    }
}
