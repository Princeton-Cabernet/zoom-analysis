
#include <chrono>
#include <cstdlib>
#include <cxxopts/cxxopts.h>
#include <iomanip>
#include <iostream>

#include "../lib/net.h"
#include "../lib/pcap_file_reader.h"
#include "../lib/rtp.h"
#include "../lib/rtp_stream_analyzer.h"
#include "../lib/util.h"
#include "../lib/zoom.h"
#include "../lib/zoom_flow_tracker.h"
#include "../lib/zoom_rtp_stream_tracker.h"

namespace zoom_rtp {

    struct config {
        std::string input_path;
        std::optional<std::string> pkts_out_path = std::nullopt;
        std::optional<std::string> streams_out_path = std::nullopt;
        std::optional<std::string> frames_out_path = std::nullopt;
        std::optional<unsigned long> limit = std::nullopt;
        std::optional<std::string> stats_out_path = std::nullopt;
    };

    void print_help(cxxopts::Options& opts, int exit_code = 0) {

        std::ostream& os = (exit_code ? std::cerr : std::cout);
        os << opts.help({""}) << std::endl;
        exit(exit_code);
    }

    cxxopts::Options set_options() {

        cxxopts::Options opts("zoom_rtp",
                              "Collects statistics about RTP streams in Zoom traffic");

        opts.add_options()
            ("i,in", "input file", cxxopts::value<std::string>(), "IN.zpkt")
            ("p,pkts-out", "output path for packet log (optional)",
                cxxopts::value<std::string>(),"OUT.csv")
            ("s,streams-out", "output path for stream summary (optional)",
                cxxopts::value<std::string>(),"OUT.csv")
            ("f,frames-out", "output path for frame log (optional)",
                cxxopts::value<std::string>(),"OUT.csv")
            ("t,stats-out", "output path for 1s statistics (optional)",
                cxxopts::value<std::string>(),"OUT.csv")
            ("l,limit", "limit to L packets (in millions)  (optional)",
                cxxopts::value<unsigned long>(), "L")
            ("h,help", "print this help message");

        return opts;
    }

    config parse_options(cxxopts::Options opts, int argc, char** argv) {

        config config{};

        auto parsed = opts.parse(argc, argv);

        if (parsed.count("i")) {
            config.input_path = parsed["i"].as<std::string>();
        } else {
            print_help(opts, 1);
        }

        if (parsed.count("p")) {
            config.pkts_out_path = parsed["p"].as<std::string>();
        }

        if (parsed.count("s")) {
            config.streams_out_path = parsed["s"].as<std::string>();
        }

        if (parsed.count("f")) {
            config.frames_out_path = parsed["f"].as<std::string>();
        }

        if (parsed.count("t")) {
            config.stats_out_path = parsed["t"].as<std::string>();
        }

        if (parsed.count(("l"))) {
            config.limit = parsed["l"].as<unsigned long>() * 1000000;
        }

        if (parsed.count("h")) {
            print_help(opts);
        }

        return config;
    }
}
