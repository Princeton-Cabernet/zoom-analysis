
#include "pcap_file_reader.h"

pcap_file_reader::pcap_file_reader(const std::string& file_name)
    : pcap_file_reader(std::vector<std::string>({ file_name })){ }

pcap_file_reader::pcap_file_reader(const std::vector<std::string>& file_names) {

    int data_link_type = PCAP_ERROR;
    std::vector<int> data_link_types = { };

    for (const auto& file_name : file_names) {

        auto pcap = pcap_open_offline(file_name.c_str(), _errbuf);

        if (pcap) {

            if ((data_link_type = pcap_datalink(pcap)) >= 0) {
                data_link_types.push_back(data_link_type);
            } else {
                throw std::runtime_error("pcap_reader: failed retrieving data link type for "
                    + file_name);
            }

            if (!data_link_types.empty() && data_link_type != data_link_types[0]) {
                throw std::runtime_error("pcap_reader: inconsistent data link types starting in "
                    + file_name);
            }

            _pcap.push_back(pcap);
            _file_count++;

        } else {
            throw std::runtime_error("pcap_reader: could not open " + file_name);
        }
    }
}

pcap_link_type pcap_file_reader::datalink_type() const {

    int data_link_type = -2;

    for (pcap* pcap : _pcap) {

        if (data_link_type == -2 && pcap_datalink(pcap) >= 0) {
            data_link_type = pcap_datalink(pcap);
        } else if (data_link_type >= 0 && pcap_datalink(pcap) != data_link_type) {
            return pcap_link_type::multiple_error;
        } else if (pcap_datalink(pcap) < 0) {
            return pcap_link_type::error;
        }
    }

    return pcap_link_type { data_link_type };
}

bool pcap_file_reader::next(pcap_pkt& pkt) {

    return next(&pkt.buf, pkt.ts, pkt.frame_len, pkt.cap_len);
}

bool pcap_file_reader::next(const unsigned char** buf, timeval& ts,
    unsigned short& frame_len, unsigned short& cap_len) {

    if (!(_pkt_count++))
        _start = std::chrono::high_resolution_clock::now();

    auto pcap_status = pcap_next_ex(_pcap[_current_file], &_hdr, &_pl_buf);

    if (pcap_status == -2) {

        if (_file_count > _current_file + 1) {
            _current_file++;
            next(buf, ts, frame_len, cap_len);
        } else {
            _done = true;
            _end = std::chrono::high_resolution_clock::now();
        }

    } else {
        *buf = _pl_buf;
        ts = _hdr->ts;
        frame_len = _hdr->len;
        cap_len = _hdr->caplen;
    }

    return !_done;
}

unsigned pcap_file_reader::file_count() const {

    return _file_count;
}

unsigned long pcap_file_reader::pkt_count() const {

    return _pkt_count;
}

double pcap_file_reader::time_in_loop() const {

    if (!_done)
        throw std::logic_error("pcap_file_reader: not yet done");

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(_end - _start);
    return (double) duration.count() / 1000000;
}

void pcap_file_reader::close() {

    for (auto* p : _pcap) {
        pcap_close(p);
        p = nullptr;
    }
}
