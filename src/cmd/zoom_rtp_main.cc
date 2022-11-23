#include "../lib/simple_binary_reader.h"
#include "../lib/zoom_offline_analyzer.h"
#include "zoom_rtp.h"

int main(int argc, char** argv) {

    auto config = zoom_rtp::parse_options(zoom_rtp::set_options(), argc, argv);

    zoom::pkt pkt;
    simple_binary_reader<zoom::pkt> pkt_reader(config.input_path);
    zoom::offline_analyzer analyzer;
    unsigned long pkt_count = 0;

    if (config.pkts_out_path) {
        analyzer.enable_pkt_log(*config.pkts_out_path);
    }

    if (config.streams_out_path) {
        analyzer.enable_streams_log(*config.streams_out_path);
    }

    if (config.frames_out_path) {
        analyzer.enable_frame_log(*config.frames_out_path);
    }

    if (config.stats_out_path) {
        analyzer.enable_stats_log(*config.stats_out_path);
    }

    std::cout << "- " << pkt_reader.size() << " packets in trace" << std::endl;

    while(pkt_reader.next(pkt)) {

        if (pkt.flags.rtp) {

            if (pkt.proto.rtp.pt == 98 || pkt.proto.rtp.pt == 99 || pkt.proto.rtp.pt == 110
                || pkt.proto.rtp.pt == 112 || pkt.proto.rtp.pt == 113) {

                analyzer.add(pkt);
            }
        }

        if ((++pkt_count % 10000000) == 0) { // every 10M packets
            std::cout << "- " << pkt_count << '/' << pkt_reader.size() << ": "
                      << (unsigned) (((double) pkt_count / (double) pkt_reader.size()) * 100) << "%"
                      << std::endl;
        }

        if (config.limit && pkt_count == *config.limit) {
            break;
        }
    }

    if (config.streams_out_path) {
        analyzer.write_streams_log();
    }

    std::cout << "- pkts: " << pkt_reader.count() << " packets"
              << (config.limit ? " (limited)" : "") << std::endl;

    std::cout << "- runtime [s]: " << pkt_reader.time_in_loop() << std::endl;

    if (config.pkts_out_path) {
        std::cout << "- wrote packets to " << *config.pkts_out_path << std::endl;
    }

    if (config.streams_out_path) {
        std::cout << "- wrote streams to " << *config.streams_out_path << std::endl;
    }

    if (config.frames_out_path) {
        std::cout << "- wrote frames to " << *config.frames_out_path << std::endl;
    }

    if (config.stats_out_path) {
        std::cout << "- wrote stats to " << *config.stats_out_path << std::endl;
    }

    pkt_reader.close();

    return 0;
}
