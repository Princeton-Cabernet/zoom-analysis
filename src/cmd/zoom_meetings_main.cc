
#include <chrono>
#include <optional>
#include <map>
#include <set>

#include "../lib/simple_binary_reader.h"
#include "../lib/util.h"
#include "../lib/zoom.h"
#include "../lib/zoom_nets.h"
#include "zoom_meetings.h"

using namespace zoom_meetings;

struct streams {

    typedef std::unordered_map<std::uint32_t, std::map<stream_key, stream_state>> container_type;

    container_type::iterator iterator_to_ssrc(std::uint32_t ssrc) {

        auto ssrc_it = data.find(ssrc);

        if (ssrc_it == data.end()) {

            auto [insert_it, success] = data.insert(
                    std::make_pair(ssrc, std::map<stream_key, stream_state>{}));

            if (success) {
                ssrc_it = insert_it;
            } else {
                throw std::runtime_error("could not insert ssrc");
            }
        }

        return ssrc_it;
    }

    std::pair<std::map<stream_key, stream_state>::iterator, bool> iterator_to_stream(const stream_key& key) {

        auto ssrc_it = iterator_to_ssrc(key.ssrc);
        auto stream_it = ssrc_it->second.find(key);
        bool inserted = false;

        if (stream_it == ssrc_it->second.end()) {

            auto [insert_it, success]
                = ssrc_it->second.insert(std::make_pair(key, stream_state{}));

            if (success) {
                stream_it = insert_it;
                inserted = true;
            } else {
                throw std::runtime_error("could not insert stream");
            }
        }

        return std::make_pair(stream_it, inserted);
    }

    std::optional<unsigned> find_duplicate(const zoom::pkt& pkt, unsigned buffer_s = 3000) {

        if (pkt.flags.rtp) {

            auto key = stream_key::from_pkt(pkt);
            auto rtp_ts = pkt.proto.rtp.ts;
            auto ssrc_it = iterator_to_ssrc(key.ssrc);

            for (const auto& [stream_key, stream_state] : ssrc_it->second) {

                if (stream_state.stream_id && rtp_ts >= (stream_state.last_rtp_ts - buffer_s)
                    && (rtp_ts <= stream_state.last_rtp_ts + buffer_s)) {

                    return stream_state.stream_id;
                }
            }

            return std::nullopt;

        } else {
            throw std::logic_error("not an rtp packet");
        }
    }

    void clean_up(unsigned min_pkts) {
        for (auto &[ssrc, stream_map]: data) {
            for (auto it = stream_map.begin(); it != stream_map.end(); ) {
                it = (it->second.pkts < min_pkts ? stream_map.erase(it) : std::next(it));
            }
        }
    }

    void copy_all_streams_sorted(std::vector<std::pair<stream_key, stream_state>>& copy_to) const {

        for (const auto& [ssrc, stream_map]: data)
            for (const auto& [stream_key, stream_state]: stream_map)
                copy_to.emplace_back(stream_key, stream_state);

        std::sort(copy_to.begin(), copy_to.end(),[](const std::pair<stream_key, stream_state>& a,
            const std::pair<stream_key, stream_state>& b) -> bool {
            return a.second.start_ts_s < b.second.start_ts_s;
        });
    }

    void print_csv_to_stream(std::ostream& os) const {

        os  << "stream_id,conn_type,start_ts_s,end_ts_s,ip_src,tp_src,ip_dst,tp_dst,zoom_type,ssrc,"
            << "start_rtp_ts,end_rtp_ts,pkts,bytes,audio_112_pkts,audio_99_pkts,audio_113_pkts"
            << std::endl;

        for (const auto& [ssrc, stream_map] : data) {
            for (const auto& [stream_key, stream_state] : stream_map) {

                os  << (stream_state.stream_id ? std::to_string(*stream_state.stream_id) : "NA") << ","
                    << (stream_key.p2p ? "udp_p2p" : "udp_srv") << ","
                    << stream_state.start_ts_s << ","
                    << stream_state.end_ts_s << ","
                    << net::ipv4::addr_to_str(stream_key.ip_src) << ","
                    << stream_key.tp_src << ","
                    << net::ipv4::addr_to_str(stream_key.ip_dst) << ","
                    << stream_key.tp_dst << ","
                    << (unsigned) stream_key.zoom_type << ","
                    << ssrc << ","
                    << stream_state.start_rtp_ts << ","
                    << stream_state.last_rtp_ts << ","
                    << stream_state.pkts << ","
                    << stream_state.bytes << ","
                    << stream_state.audio_112_pkts << ","
                    << stream_state.audio_99_pkts << ","
                    << stream_state.audio_113_pkts
                    << std::endl;
            }
        }
    }

    container_type data;
    unsigned next_unique_stream_id = 0;
};

class meeting_grouper {

public:

    struct meeting_assignment {
        unsigned meeting_id = 0;
        long int expiration = 0;
    };

    struct match {

        std::optional<unsigned> stream_id = {}, ip_port = {}, ip = {};

        [[nodiscard]] unsigned match_count() const {

            unsigned n = 0;
            n +=  stream_id ? 1 : 0;
            n +=  ip ? 1 : 0;
            n +=  ip_port ? 1 : 0;
            return n;
        }

        [[nodiscard]] std::set<unsigned> matched_meetings() const {

            std::set<unsigned> s;

            if (stream_id)
                s.insert(*stream_id);

            if (ip)
                s.insert(*ip);

            if (ip_port)
                s.insert(*ip_port);

            return s;
        }
    };

    void add_stream(const stream_key& stream_key, const stream_state& stream_state) {

        if (!stream_state.stream_id) {
            std::cerr << "meeting_grouper: add_stream: stream does not have a stream id"
                      << std::endl;

            return;
        }

        auto match = _match(stream_key, stream_state);
        auto client_ip_port = _client_ip_port(stream_key);
        auto matched_meetings = match.matched_meetings();

        unsigned meeting_id = 0;

        if (match.match_count() == 0) {  // no match -> new meeting

            meeting_id = _next_meeting_id++;

        } else { // at least one match -> tag onto existing meeting

            if (matched_meetings.size() == 1) { // single match

                meeting_id = *(match.matched_meetings().begin());

            } else if (matched_meetings.size() == 2) { // 2 (different) matches

                auto from_meeting_id = *(match.matched_meetings().begin());
                auto to_meeting_id   = *(++match.matched_meetings().begin());
                _merge(from_meeting_id, to_meeting_id);
                meeting_id = to_meeting_id;

            } else {
                //TODO: more matches - handle this cae
            }
        }

        _streams[*stream_state.stream_id] = meeting_assignment{meeting_id, stream_state.end_ts_s + 3600};
        _ip_ports[client_ip_port] = meeting_assignment{meeting_id, stream_state.end_ts_s + 3600};
        _ips[client_ip_port.ip] = meeting_assignment{meeting_id, stream_state.end_ts_s + 3600};
        _meetings[meeting_id].push_back(std::make_pair(stream_key, stream_state));
    }

    inline unsigned long meeting_count() const {

        return _meetings.size();
    }

    void print_meetings_csv_to_stream(std::ostream& os) {

        os  << "meeting_id,stream_id,conn_type,start_ts_s,end_ts_s,ip_src,tp_src,ip_dst,tp_dst,"
            << "zoom_type,ssrc,start_rtp_ts,end_rtp_ts,pkts,bytes,audio_112_pkts,audio_99_pkts,"
            << "audio_113_pkts"
            << std::endl;

        for (const auto& [meeting_id, streams] : _meetings) {
            for (const auto& [stream_key, stream_state] : streams) {

                os  << meeting_id << ","
                    << (stream_state.stream_id ? std::to_string(*stream_state.stream_id) : "NA") << ","
                    << (stream_key.p2p ? "udp_p2p" : "udp_srv") << ","
                    << stream_state.start_ts_s << ","
                    << stream_state.end_ts_s << ","
                    << net::ipv4::addr_to_str(stream_key.ip_src) << ","
                    << stream_key.tp_src << ","
                    << net::ipv4::addr_to_str(stream_key.ip_dst) << ","
                    << stream_key.tp_dst << ","
                    << (unsigned) stream_key.zoom_type << ","
                    << stream_key.ssrc << ","
                    << stream_state.start_rtp_ts << ","
                    << stream_state.last_rtp_ts << ","
                    << stream_state.pkts << ","
                    << stream_state.bytes << ","
                    << stream_state.audio_112_pkts << ","
                    << stream_state.audio_99_pkts << ","
                    << stream_state.audio_113_pkts
                    << std::endl;
            }
        }
    }

private:

    [[nodiscard]] match _match(const stream_key& stream_key, const stream_state& stream_state) const {

        auto client_ip_port = _client_ip_port(stream_key);

        match m;

        auto streams_it  = _streams.find(*stream_state.stream_id);

        if (streams_it != _streams.end() && stream_state.start_ts_s < streams_it->second.expiration) {
            m.stream_id = streams_it->second.meeting_id;
        }


        auto ip_ports_it = _ip_ports.find(client_ip_port);

        if (ip_ports_it != _ip_ports.end() && stream_state.start_ts_s < ip_ports_it->second.expiration) {
            m.ip_port = ip_ports_it->second.meeting_id;
        }


        auto ips_it = _ips.find(client_ip_port.ip);

        if (ips_it != _ips.end() && stream_state.start_ts_s < ips_it->second.expiration) {
            m.ip = ips_it->second.meeting_id;
        }

        return m;
    }

    void _merge(unsigned from, unsigned to) {

        for (auto& [_, meeting_assignment]: _streams) {
            if (meeting_assignment.meeting_id == from)
                meeting_assignment.meeting_id = to;
        }

        for (auto& [_, meeting_assignment]: _ip_ports) {
            if (meeting_assignment.meeting_id == from)
                meeting_assignment.meeting_id = to;
        }

        for (auto& [_, meeting_assignment]: _ips) {
            if (meeting_assignment.meeting_id == from)
                meeting_assignment.meeting_id = to;
        }

        auto from_meeting = _meetings.find(from);
        auto to_meeting   = _meetings.find(to);

        if (from_meeting == _meetings.end() || to_meeting == _meetings.end())
            throw std::invalid_argument("_merge: invalid meeting ids");

        auto& from_streams = from_meeting->second;
        auto& to_streams   = to_meeting->second;

        to_streams.insert(to_streams.end(), from_streams.begin(), from_streams.end());
        _meetings.erase(from_meeting);
    }

    static net::ipv4_port _client_ip_port(const stream_key& k) {

        if (zoom::nets::match(k.ip_src)) { // src is a zoom server -> return dst
            return net::ipv4_port{k.ip_dst, k.tp_dst};
        } else if (zoom::nets::match(k.ip_dst)) { // dst is a zoom server -> return src
            return net::ipv4_port{k.ip_src, k.tp_src};
        } else { // neither is a zoom server -> return smaller ip address
            if (k.ip_src < k.ip_dst) {
                return net::ipv4_port{k.ip_src, k.tp_src};
            } else {
                return net::ipv4_port{k.ip_dst, k.tp_dst};
            }
        }
    }

    unsigned _timeout_s = 3600;
    unsigned _next_meeting_id = 0;
    std::map<unsigned, meeting_assignment> _streams;
    std::map<net::ipv4_port, meeting_assignment> _ip_ports;
    std::map<std::uint32_t, meeting_assignment> _ips;
    std::map<unsigned, std::vector<std::pair<stream_key, stream_state>>> _meetings;
};

int main(int argc, char** argv) {

    auto config = parse_options(set_options(), argc, argv);
    auto start = std::chrono::high_resolution_clock::now();

    simple_binary_reader<zoom::pkt> zpkt_reader(config.input_file_name);

    zoom::pkt pkt;
    struct { unsigned long total_pkts = 0, media_pkts = 0, streams = 0; } counters;

    auto is_media_pkt = [](const zoom::pkt& pkt) {
        return pkt.flags.rtp && (pkt.proto.rtp.pt == 98 || pkt.proto.rtp.pt == 112
            || pkt.proto.rtp.pt == 99 || pkt.proto.rtp.pt == 113);
    };

    struct streams streams;

    while (zpkt_reader.next(pkt)) {

        counters.total_pkts++;

        if (!is_media_pkt(pkt)) continue;

        counters.media_pkts++;

        auto [stream_it, inserted] = streams.iterator_to_stream(stream_key::from_pkt(pkt));
        auto& stream_state = stream_it->second;
        stream_state.update_with_pkt(pkt);

        if (inserted) { // if new stream, check if this is a 'duplicate' of any other stream

            counters.streams++;

            auto duplicate_id = streams.find_duplicate(pkt);

            if (duplicate_id) {
                stream_it->second.stream_id = *duplicate_id;
            } else {
                stream_it->second.stream_id = streams.next_unique_stream_id++;
            }
        }
    }

    zpkt_reader.close();

    // group into meetings:

    streams.clean_up(10); // ignore streams with < 10 packets

    std::vector<std::pair<stream_key, stream_state>> sorted_streams;

    streams.copy_all_streams_sorted(sorted_streams);

    meeting_grouper grouper;

    for (const auto& [stream_key, stream_state]: sorted_streams) {
        grouper.add_stream(stream_key, stream_state);
    }

    // produce output files:

    if (config.unique_streams_output_file_name) {

        std::ofstream fs(*config.unique_streams_output_file_name);

        if (fs.is_open()) {
            streams.print_csv_to_stream(fs);
            fs.close();
            std::cout << " - wrote unique streams to " << *config.unique_streams_output_file_name
                      << std::endl;
        } else {
            std::cerr << "could not open file for writing: "
                      << *config.unique_streams_output_file_name << std::endl;
        }
    }

    if (config.meetings_output_file_name) {

        std::ofstream fs(*config.meetings_output_file_name);

        if (fs.is_open()) {
            grouper.print_meetings_csv_to_stream(fs);
            fs.close();
            std::cout << " - wrote meetings to " << *config.meetings_output_file_name
                      << std::endl;
        } else {
            std::cerr << "could not open file for writing: "
                      << *config.meetings_output_file_name << std::endl;
        }
    }

    std::cout << " - total pkts: " << counters.total_pkts << std::endl;
    std::cout << " - media pkts: " << counters.media_pkts << std::endl;
    std::cout << " - media streams: " << counters.streams << std::endl;
    std::cout << " - unique streams: " << streams.next_unique_stream_id << std::endl;
    std::cout << " - meetings: " << grouper.meeting_count() << std::endl;
    std::cout << " - runtime: " << util::seconds_since(start) << " s" << std::endl;

    return 0;
}
