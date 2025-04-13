
#include <array>

#include "zoom_flows.h"
#include "../lib/zoom.h"
#include "../lib/simple_binary_writer.h"
#include "../lib/mac_counter.h"

int main(int argc, char** argv) {

    auto config = zoom_flows::parse_options(zoom_flows::set_options(), argc, argv);
    pcap_file_writer pcap_out;
    std::ofstream flows_out, types_out, rate_out;
    simple_binary_writer<zoom::pkt> zpkt_writer;

    auto in_files = util::files_in_directory(config.input_path, "pcap");
    std::sort(in_files.begin(), in_files.end(), util::compare_file_ext_seq);

    if (config.pcap_out_file_name) {
        pcap_out.open(*config.pcap_out_file_name, pcap_link_type::eth);
    }

    if (config.flows_out_file_name) {
        flows_out.open(*config.flows_out_file_name);

        if (!flows_out.is_open()) {
            std::cerr << "error: could not open flows output file " << *config.flows_out_file_name
                      << ", exiting." << std::endl;
            exit(1);
        }
    }

    if (config.types_out_file_name) {
        types_out.open(*config.types_out_file_name);

        if (!types_out.is_open()) {
            std::cerr << "error: could not open types output file " << *config.types_out_file_name
                      << ", exiting." << std::endl;
            exit(1);
        }
    }

    if (config.rate_out_file_name) {
        rate_out.open(*config.rate_out_file_name);

        if (!rate_out.is_open()) {
            std::cerr << "error: could not open rate output file " << *config.rate_out_file_name
                      << ", exiting." << std::endl;
            exit(1);
        }
    }

    if (config.zpkt_out_file_name) {
        zpkt_writer.open(*config.zpkt_out_file_name);
    }

    pcap_pkt pkt;
    zoom::flow_tracker flow_tracker;
    mac_counter mac_counter;

    struct pkts_bytes {
        unsigned long pkts = 0, bytes = 0;

        void increment(unsigned long pkts_inc, unsigned long bytes_inc) {
            pkts += pkts_inc;
            bytes += bytes_inc;
        }
    };

    std::array<pkts_bytes, 256> p2p_inner_types, srv_inner_types, srv_outer_types;

    pcap_file_reader pcap_in(in_files);

    if (pcap_in.datalink_type() != pcap_link_type::eth) {
        std::cerr << "error: only ethernet supported right now, exiting." << std::endl;
        exit(1);
    }

    unsigned last_ts = 0;
    std::uint64_t last_total_pkt_count = 0, last_zoom_pkt_count = 0, last_zoom_byte_count = 0;


    while (pcap_in.next(pkt)) {

        if (config.rate_out_file_name) {
            mac_counter.add(((net::eth::hdr*) pkt.buf)->src_addr);

            if (last_ts == 0) {
                last_ts = pkt.ts.tv_sec;
                last_total_pkt_count = mac_counter.count();

                rate_out << "ts_s,total_pkts,zoom_pkts,zoom_bytes" << std::endl;
            }

            if (pkt.ts.tv_sec > last_ts) {

                std::uint64_t current_total_pkt_count = mac_counter.count();
                std::uint64_t current_zoom_pkt_count = flow_tracker.count_zoom_pkts_detected();
                std::uint64_t current_zoom_byte_count = flow_tracker.count_zoom_bytes_detected();

                rate_out << last_ts << ","
                         << (current_total_pkt_count - last_total_pkt_count)
                         << "," << (current_zoom_pkt_count - last_zoom_pkt_count)
                         << "," << (current_zoom_byte_count - last_zoom_byte_count)
                         << std::endl;

                last_ts = pkt.ts.tv_sec;
                last_total_pkt_count = current_total_pkt_count;
                last_zoom_pkt_count = current_zoom_pkt_count;
                last_zoom_byte_count = current_zoom_byte_count;
            }
        }

        // must be IPv4
        if (net::eth::type_from_buf(pkt.buf) != net::eth::type::ipv4) continue;

        auto ip_5t = net::ipv4_5tuple::from_ipv4_pkt_data(pkt.buf + net::eth::HDR_LEN);
        auto zoom_flow = flow_tracker.track(ip_5t, pkt.ts, pkt.frame_len);

        if (zoom_flow) {

            // p2p-only option:
            if (config.p2p_only && !zoom_flow->is_p2p() && !zoom_flow->is_stun()) continue;

            auto hdr = zoom::parse_zoom_pkt_buf(pkt.buf, true, zoom_flow->is_p2p());

            if (zoom_flow->type == zoom::flow_tracker::flow_type::udp_p2p) {
                p2p_inner_types[hdr.zoom_inner[0]].increment(1, ntohs(hdr.udp->dgram_len));
            } else if (zoom_flow->type == zoom::flow_tracker::flow_type::udp_srv) {

                srv_outer_types[hdr.zoom_outer[0]].increment(1, ntohs(hdr.udp->dgram_len));

                if (hdr.zoom_outer[0] == zoom::SRV_MEDIA_TYPE) {
                    srv_inner_types[hdr.zoom_inner[0]].increment(1, ntohs(hdr.udp->dgram_len));
                }
            }

            if (config.zpkt_out_file_name && zoom_flow->is_udp()) {
                zoom::pkt zpkt{hdr, pkt.ts, pkt.frame_len, zoom_flow->is_p2p()};
                zpkt_writer.write(zpkt);
            }

            if (config.pcap_out_file_name) {
                pcap_out.write(pkt);
            }
        }

        if ((pcap_in.pkt_count() % 10000000) == 0) {
            std::cout << "- " << pcap_in.pkt_count() << std::endl;
        }
    }

    pcap_in.close();

    if (config.pcap_out_file_name) {
        pcap_out.close();
    }

    if (config.flows_out_file_name) {
        flows_out << "flow_id,ip_proto,ip_src,tp_src,ip_dst,tp_dst,type,pkts,bytes,"
                  << "start_ts_tvs,start_ts_tvus,end_ts_tvs,end_ts_tvus" << std::endl;

        for (const auto& [ip_5t, stats]: flow_tracker.flows()) {
            flows_out << stats.id << "," << ip_5t << ","
                      << zoom::flow_tracker::flow_type_string(stats.type) << "," << stats.pkts << ","
                      << stats.bytes << "," << stats.start_ts.tv_sec << "," << stats.start_ts.tv_usec
                      << "," << stats.last_ts.tv_sec << "," << stats.last_ts.tv_usec << std::endl;
        }

        flows_out.close();
    }

    if (config.types_out_file_name) {

        types_out << "mode,outer_type,inner_type,pkts,bytes" << std::endl;

        for (unsigned type = 0; type < 256; type++) {
            if (p2p_inner_types[type].pkts > 0) {
                types_out << "p2p,NA," << (unsigned) type << "," << p2p_inner_types[type].pkts
                          << "," << p2p_inner_types[type].bytes << std::endl;
            }
        }

        for (unsigned type = 0; type < 256; type++) {
            if (srv_inner_types[type].pkts > 0) {
                types_out << "srv,5," << (unsigned) type << "," << srv_inner_types[type].pkts
                          << "," << srv_inner_types[type].bytes << std::endl;
            }
        }

        for (unsigned type = 0; type < 256; type++) {
            if (type != 5 && srv_outer_types[type].pkts > 0) {
                types_out << "srv," << (unsigned) type << ",NA," << srv_outer_types[type].pkts
                          << "," << srv_outer_types[type].bytes << std::endl;
            }
        }

        types_out.close();
    }

    if (config.zpkt_out_file_name) {
        zpkt_writer.close();
    }

    std::cout << "- input files: " << pcap_in.file_count() << std::endl;
    std::cout << "- total pkts: " << flow_tracker.count_total_pkts_processed() << std::endl;
    std::cout << "- zoom pkts: " << flow_tracker.count_zoom_pkts_detected() << std::endl;
    std::cout << "- zoom flows: " << flow_tracker.count_zoom_flows_detected() << std::endl;
    std::cout << "- runtime [s]: " << std::fixed << std::setw(3) << pcap_in.time_in_loop()
              << std::endl;

    if (config.flows_out_file_name) {
        std::cout << "- wrote flow summary to " << *config.flows_out_file_name << std::endl;
    }

    if (config.types_out_file_name) {
        std::cout << "- wrote type summary to " << *config.types_out_file_name << std::endl;
    }

    if (config.rate_out_file_name) {
        std::cout << "- wrote rate summary to " << *config.rate_out_file_name << std::endl;
    }

    if (config.pcap_out_file_name) {
        std::cout << "- wrote " << pcap_out.count() << " filtered packets to "
                  << *config.pcap_out_file_name << std::endl;
    }

    if (config.zpkt_out_file_name) {
        std::cout << "- wrote " << zpkt_writer.count() << " filtered packets to "
                  << *config.zpkt_out_file_name << std::endl;
    }

    return 0;
}
