#ifndef VCA_ANALYSIS_PCAP_HELPERS_H
#define VCA_ANALYSIS_PCAP_HELPERS_H

#include <cstdlib>
#include <iomanip>
#include <ostream>

struct pcap_pkt {
    const unsigned char *buf = nullptr;
    timeval ts = { 0, 0 };
    unsigned short frame_len = 0, cap_len = 0;
};

enum class pcap_link_type : int {
    error          = -2,
    multiple_error = -1,
    null           = 0,
    eth            = 1,
    raw            = 101,
    loop           = 108
};

static bool operator<(const timeval& a, const timeval& b) {

    if (a.tv_sec == b.tv_sec) {
        return a.tv_usec < b.tv_usec;
    } else {
        return a.tv_sec < b.tv_sec;
    }
}

static bool operator==(const timeval& a, const timeval& b) {
    return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec;
}

static bool operator>(const timeval& a, const timeval& b) {
    return !(a == b) && !(a < b);
}

static bool operator>=(const timeval& a, const timeval& b) {
    return a == b || a > b;
}

static timeval operator-(const timeval& a, const timeval& b) {

    timeval res {0, 0};
    res.tv_sec = a.tv_sec - b.tv_sec;
    res.tv_usec = a.tv_usec - b.tv_usec;

    if (res.tv_usec < 0) {
        res.tv_sec -= 1;
        res.tv_usec += 1000000;
    }

    return res;
}

static std::ostream& operator<<(std::ostream& os, const timeval& tv) {
    return os << std::dec << (unsigned long) tv.tv_sec << "," << std::dec << (unsigned) tv.tv_usec;
}

#endif
