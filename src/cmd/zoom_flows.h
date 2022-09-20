
#include <chrono>
#include <cxxopts/cxxopts.h>
#include <filesystem>
#include <optional>
#include <iostream>

#include "../lib/net.h"
#include "../lib/pcap_file_reader.h"
#include "../lib/pcap_file_writer.h"
#include "../lib/util.h"
#include "../lib/zoom_flow_tracker.h"

namespace zoom_flows {

    struct config {
        std::string input_path;

        std::optional<std::string> flows_out_file_name = std::nullopt;
        std::optional<std::string> pcap_out_file_name  = std::nullopt;
        std::optional<std::string> types_out_file_name = std::nullopt;
        std::optional<std::string> rate_out_file_name  = std::nullopt;
        std::optional<std::string> zpkt_out_file_name  = std::nullopt;

        bool p2p_only = false;
    };

    void print_help(cxxopts::Options& opts, int exit_code = 0) {

        std::ostream& os = (exit_code ? std::cerr : std::cout);
        os << opts.help({""}) << std::endl;
        exit(exit_code);
    }

    cxxopts::Options set_options() {

        cxxopts::Options opts("zoom_flows",
                              "Extracts packets associated with Zoom and writes per-flow statistics");

        opts.add_options()
                ("i,in", "input file/path",
                 cxxopts::value<std::string>(),"IN.pcap or IN/")
                ("f,flows-out", "flow summary output file (optional)",
                 cxxopts::value<std::string>(), "OUT.csv")
                ("t,types-out", "type summary output file (optional)",
                 cxxopts::value<std::string>(), "OUT.csv")
                ("p,pcap-out", "filtered pcap output file (optional)",
                 cxxopts::value<std::string>(),"OUT.pcap")
                ("r,rate-out", "packet rate output file (optional)",
                 cxxopts::value<std::string>(), "OUT.csv")
                ("z,zpkt-out", "zoom packets binary output file (optional)",
                 cxxopts::value<std::string>(),"OUT.zpkt")
                ("2,p2p-only", "only process STUN and P2P packets")
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

        if (parsed.count("f")) {
            config.flows_out_file_name = parsed["f"].as<std::string>();
        }

        if (parsed.count("p")) {
            config.pcap_out_file_name = parsed["p"].as<std::string>();
        }

        if (parsed.count("t")) {
            config.types_out_file_name = parsed["t"].as<std::string>();
        }

        if (parsed.count("r")) {
            config.rate_out_file_name = parsed["r"].as<std::string>();
        }

        if (parsed.count("z")) {
            config.zpkt_out_file_name = parsed["z"].as<std::string>();
        }

        if (parsed.count("h")) {
            print_help(opts);
        }

        config.p2p_only = parsed.count("2");

        return config;
    }
}
