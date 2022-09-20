
#include "net.h"

net::ipv4_5tuple net::ipv4_5tuple::from_ipv4_pkt_data(const unsigned char* pkt_data) {

    ipv4_5tuple ip4_5_tuple{};

    auto ipv4 = (net::ipv4::hdr*) pkt_data;
    ip4_5_tuple.ip_src   = ntohl(ipv4->src_addr);
    ip4_5_tuple.ip_dst   = ntohl(ipv4->dst_addr);
    ip4_5_tuple.ip_proto = ipv4->next_proto_id;

    if (ipv4->next_proto_id == 6 || ipv4->next_proto_id == 17) {
        auto tp_hdr = (net::tcp_or_udp_hdr*) (pkt_data + ipv4->ihl_bytes());
        ip4_5_tuple.tp_src = ntohs(tp_hdr->src_port);
        ip4_5_tuple.tp_dst = ntohs(tp_hdr->dst_port);
    }

    return ip4_5_tuple;
}
