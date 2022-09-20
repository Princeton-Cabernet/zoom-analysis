
#ifndef ZOOM_ANALYSIS_PCAP_FILE_WRITER_H
#define ZOOM_ANALYSIS_PCAP_FILE_WRITER_H

#include <string>
#include <stdexcept>
#include <pcap.h>
#include "pcap_util.h"

class pcap_file_writer {
public:
    pcap_file_writer() = default;
    explicit pcap_file_writer(const std::string& file_name, pcap_link_type link_type);
    void open(const std::string& file_name, pcap_link_type link_type);
    void write(const pcap_pkt& pkt);
    void write(const unsigned char** buf, const timeval& timestamp,
               unsigned short frame_len, unsigned short cap_len);
    [[nodiscard]] unsigned long count() const;
    void close();
private:
    pcap_t* _pcap = nullptr;
    pcap_dumper_t* _pcap_dumper = nullptr;
    unsigned long _count = 0;
};

#endif
