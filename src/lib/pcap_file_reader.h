#ifndef ZOOM_ANALYSIS_PCAP_FILE_READER_H
#define ZOOM_ANALYSIS_PCAP_FILE_READER_H

#include <chrono>
#include <vector>
#include <string>
#include <stdexcept>
#include <pcap.h>

#include "pcap_util.h"

class pcap_file_reader {
public:
    explicit pcap_file_reader(const std::string& file_name);
    explicit pcap_file_reader(const std::vector<std::string>& file_names);
    [[nodiscard]] pcap_link_type datalink_type() const;
    bool next(pcap_pkt& pkt);
    bool next(const unsigned char** buf, timeval& ts, unsigned short& frame_len,
              unsigned short& cap_len);
    [[nodiscard]] unsigned file_count() const;
    [[nodiscard]] unsigned long pkt_count() const;
    [[nodiscard]] double time_in_loop() const;
    void close();
    ~pcap_file_reader() = default;

private:
    std::vector<pcap*> _pcap;
    struct pcap_pkthdr* _hdr = {};
    const u_char* _pl_buf = {};
    char _errbuf[PCAP_ERRBUF_SIZE] = {};
    bool _done = false;
    unsigned _current_file = 0, _file_count = 0;
    unsigned long _pkt_count = 0;
    std::chrono::high_resolution_clock::time_point _start, _end;
};

#endif
