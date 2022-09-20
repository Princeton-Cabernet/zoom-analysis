
#include "../lib/zoom.h"
#include <cxxopts/cxxopts.h>
#include <iostream>
#include <optional>
#include <tuple>

namespace zoom_meetings {

    struct config {
        std::string input_file_name;
        std::optional<std::string> unique_streams_output_file_name = std::nullopt;
        std::optional<std::string> meetings_output_file_name = std::nullopt;
        // unsigned timeout = 3600;
    };

    void print_help(cxxopts::Options &opts, int exit_code = 0) {

        std::ostream &os = (exit_code ? std::cerr : std::cout);
        os << opts.help({""}) << std::endl;
        exit(exit_code);
    }

    cxxopts::Options set_options() {

        cxxopts::Options opts("zoom_meetings", "");

        opts.add_options()
            ("i,in", "input file name", cxxopts::value<std::string>(), "IN.zpkt")
            ("u,unique-out", "unique streams out file name (optional)",
                cxxopts::value<std::string>(),"STREAMS.csv")
            ("m,meetings-out", "meetings out file name (optional)",
                cxxopts::value<std::string>(), "MEETINGS.csv")
//          ("t,timeout", "timeout in sec. (default: 3600)", cxxopts::value<unsigned>(), "T")
            ("h,help", "print this help message");

        return opts;
    }

    config parse_options(cxxopts::Options opts, int argc, char **argv) {

        config config{};

        auto parsed = opts.parse(argc, argv);

        if (parsed.count("i")) {
            config.input_file_name = parsed["i"].as<std::string>();
        } else {
            print_help(opts, 1);
        }

        if (parsed.count("u")) {
            config.unique_streams_output_file_name = parsed["u"].as<std::string>();
        }

        if (parsed.count("m")) {
            config.meetings_output_file_name = parsed["m"].as<std::string>();
        }

        /*
        if (parsed.count("t")) {
            config.timeout = parsed["t"].as<unsigned>();
        }
        */

        if (parsed.count("h")) {
            print_help(opts);
        }

        return config;
    }

    struct stream_key {

        std::uint32_t ssrc = 0;
        std::uint32_t ip_src = 0;
        std::uint16_t tp_src = 0;
        std::uint32_t ip_dst = 0;
        std::uint16_t tp_dst = 0;
        std::uint8_t zoom_type = 0;
        bool p2p = false;

        bool operator<(const stream_key &other) const {

            return std::tie(ssrc, ip_src, tp_src, ip_dst, tp_dst, zoom_type, p2p) <
                   std::tie(other.ssrc, other.ip_src, other.tp_src, other.ip_dst, other.tp_dst,
                            other.zoom_type, other.p2p);
        }

        static struct stream_key from_pkt(const zoom::pkt& pkt) {

            if (pkt.flags.rtp) {
                return stream_key {
                    .ssrc      = pkt.proto.rtp.ssrc,
                    .ip_src    = pkt.ip_5t.ip_src,
                    .tp_src    = pkt.ip_5t.tp_src,
                    .ip_dst    = pkt.ip_5t.ip_dst,
                    .tp_dst    = pkt.ip_5t.tp_dst,
                    .zoom_type = pkt.zoom_media_type,
                    .p2p       = (bool) pkt.flags.p2p
                };
            } else {
                throw std::logic_error("stream_key::from_pkt: pkt record is not an rtp packet");
            }
        }
    };

    struct stream_state {
        std::uint32_t start_ts_s     = 0;
        std::uint32_t end_ts_s       = 0;
        std::uint32_t start_rtp_ts   = 0;
        std::uint32_t last_rtp_ts    = 0;
        std::uint32_t pkts           = 0;
        std::uint32_t bytes          = 0;
        std::uint32_t audio_112_pkts = 0;
        std::uint32_t audio_99_pkts  = 0;
        std::uint32_t audio_113_pkts = 0;
        std::optional<unsigned> stream_id = std::nullopt;

        void update_with_pkt(const zoom::pkt& pkt) {

            if (pkt.flags.rtp) {

                if (start_ts_s == 0 || pkt.ts.s < start_ts_s) {
                    start_ts_s = pkt.ts.s;
                }

                if (end_ts_s == 0 || pkt.ts.s > end_ts_s) {
                    end_ts_s = pkt.ts.s;
                }

                if (start_rtp_ts == 0 || pkt.proto.rtp.ts < start_rtp_ts) {
                    start_rtp_ts = pkt.proto.rtp.ts;
                }

                if (last_rtp_ts == 0 || pkt.proto.rtp.ts > last_rtp_ts) {
                    last_rtp_ts = pkt.proto.rtp.ts;
                }

                pkts += 1;
                bytes += pkt.udp_pl_len;

                if (pkt.zoom_media_type == 15) {
                    if (pkt.proto.rtp.pt == 112) {
                        audio_112_pkts += 1;
                    } else if (pkt.proto.rtp.pt == 99) {
                        audio_99_pkts += 1;
                    } else if (pkt.proto.rtp.pt == 113) {
                        audio_113_pkts += 1;
                    }
                }

            } else {
                throw std::logic_error("stream_key::from_pkt: pkt record is not an rtp packet");
            }
        }

    };
}
