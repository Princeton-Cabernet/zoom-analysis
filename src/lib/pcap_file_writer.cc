
#include "pcap_file_writer.h"

pcap_file_writer::pcap_file_writer(const std::string& file_name, pcap_link_type link_type) {

    open(file_name, link_type);
}

void pcap_file_writer::open(const std::string& file_name, pcap_link_type link_type) {

    if (!(_pcap = pcap_open_dead((int) link_type, 65535)))
        throw std::runtime_error("pcap_file_writer: could not initialize pcap_t");

    if (!(_pcap_dumper = pcap_dump_open(_pcap, file_name.c_str())))
        throw std::runtime_error("pcap_file_writer: could not open pcap dump for" + file_name);
}

void pcap_file_writer::write(const pcap_pkt& pkt) {

    struct pcap_pkthdr pcap_hdr {
        .ts = pkt.ts,
        .caplen = pkt.cap_len,
        .len = pkt.frame_len
    };

    pcap_dump((u_char*) _pcap_dumper, &pcap_hdr, pkt.buf);
    _count++;
}

void pcap_file_writer::write(const unsigned char** buf, const timeval& timestamp,
    unsigned short frame_len, unsigned short cap_len) {

    struct pcap_pkthdr pcap_hdr {
        .ts = timestamp,
        .caplen = cap_len,
        .len = frame_len
    };

    pcap_dump((u_char*) _pcap_dumper, &pcap_hdr, *buf);
    _count++;
}

unsigned long pcap_file_writer::count() const {
    return _count;
}

void pcap_file_writer::close() {

    pcap_close(_pcap);
    pcap_dump_close(_pcap_dumper);
    _pcap = nullptr;
    _pcap_dumper = nullptr;
}
