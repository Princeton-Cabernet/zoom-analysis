#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#if __TARGET_TOFINO__ == 2
#define RECIRCULATION_PORT 6
#else
#define RECIRCULATION_PORT 68
// #define RECIRCULATION_PORT 196
#endif

// Typedefs

typedef bit<48>  mac_addr_t;
typedef bit<32>  ipv4_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOL_TCP = 6;
const ip_protocol_t IP_PROTOCOL_UDP = 17;

const bit<8> ZOOM_TYPE_SERVER = 5;
const bit<8> CONTENT_TYPE_VIDEO = 16;
const bit<8> CONTENT_TYPE_AUDIO = 15;
const bit<8> CONTENT_TYPE_SCREENSHARE_P2P    = 30;
const bit<8> CONTENT_TYPE_SCREENSHARE_SERVER = 13;
const bit<8> CONTENT_TYPE_RTCP = 33;

// Headers

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header zoom_type_h {
    bit<8> zoom_type;
}

header zoom_outer_h {
    bit<16> outer_sequence;
    bit<32> zoom_id_zero;
    bit<8>  direction;
}

header zoom_inner_server_h {
    bit<8>  zoom_type;
    bit<56> zoom_id_one;
    bit<8>  zoom_id_two;
    bit<16> packet_sequence;
    bit<32> zoom_timestamp;
}

header zoom_inner_p2p_h {
    bit<56> zoom_id_one;
    bit<8>  zoom_id_two;
    bit<16> packet_sequence;
    bit<32> zoom_timestamp;
}

header zoom_video_inner_h {
    bit<32> zoom_id_three;
    bit<32> frame_sequence;
    bit<8>  zoom_id_four;
}

header zoom_audio_inner_h {
    bit<32> padding;
}

header zoom_screenshare_p2p_inner_h {
    bit<40> padding;
}

header zoom_screenshare_server_inner_h {
    bit<96> padding;
}

header zoom_rtcp_inner_h {
    bit<8> padding;
}

header rtp_h {
    bit<2>  version;
    bit<1>  padding;
    bit<1>  extension;
    bit<4>  csrc_count;
    bit<1>  marker;
    bit<7>  payload_type;
    bit<16> rtp_sequence;
    bit<32> rtp_timestamp;
    bit<32> ssrc;
}

header rtcp_h {
    bit<16> rtcp_type;
    bit<16> rtcp_length;
    bit<32> rtp_ssrc;
}

header rtp_extension_h {
    bit<16> bede;
    bit<16> ext_length;
}

header rtp_extension_one_h {
    bit<4> ext_one_id;
    bit<4> ext_one_len;
    bit<8> ext_one_data;
}

header rtp_extension_two_h {
    bit<4>  ext_two_id;
    bit<4>  ext_two_len;
    bit<16> ext_two_data;
    bit<16> ext_two_padding;
}

header rtp_extension_three_h {
    bit<4>  ext_third_id;
    bit<4>  ext_third_len;
    bit<32> ext_third_data;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    zoom_type_h  zoom_type;
    zoom_outer_h zoom_outer;
    zoom_inner_server_h zoom_inner_server;
    zoom_inner_p2p_h    zoom_inner_p2p;
    zoom_video_inner_h  zoom_video_inner;
    zoom_audio_inner_h  zoom_audio_inner;
    zoom_screenshare_p2p_inner_h    zoom_screenshare_p2p_inner;
    zoom_screenshare_server_inner_h zoom_screenshare_server_inner;
    zoom_rtcp_inner_h zoom_rtcp_inner;
    rtp_h  rtp;
    rtcp_h rtcp;
    rtp_extension_h       rtp_extension;
    rtp_extension_one_h   rtp_extension_one;
    rtp_extension_two_h   rtp_extension_two;
    rtp_extension_three_h rtp_extension_three;
}

struct metadata_t {
    bit<8> index;
}

struct empty_header_t {}

struct empty_metadata_t {}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1: parse_resubmit;
            0: parse_port_metadata;
        }
    }

    state parse_resubmit {
        // pkt.advance(128); // tofino2 resubmit metadata size
        // transition accept;
        transition reject;
    }
    
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {

        ig_md.index = 0;

        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default        : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            IP_PROTOCOL_UDP : parse_udp;
            IP_PROTOCOL_TCP : parse_tcp;
            default         : reject;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select (hdr.udp.udp_total_len) {
            0 .. 72 : reject;
            _       : parse_zoom_type;
            default : reject;
        }
    }

    state parse_zoom_type {
        pkt.extract(hdr.zoom_type);
        transition select (hdr.zoom_type.zoom_type) {
            ZOOM_TYPE_SERVER : parse_zoom_outer;
            default          : parse_zoom_inner_p2p;
        }
    }

    state parse_zoom_outer {
        pkt.extract(hdr.zoom_outer);
        transition parse_zoom_inner_server;
    }

    state parse_zoom_inner_server {
        pkt.extract(hdr.zoom_inner_server);
        transition parse_zoom_content_server;
    }

    state parse_zoom_inner_p2p {
        pkt.extract(hdr.zoom_inner_p2p);
        transition parse_zoom_content_p2p;
    }

    state parse_zoom_content_server {
        transition select (hdr.zoom_inner_server.zoom_type) {
            CONTENT_TYPE_VIDEO : parse_zoom_video_inner;
            CONTENT_TYPE_AUDIO : parse_zoom_audio_inner;
            CONTENT_TYPE_SCREENSHARE_P2P    : parse_zoom_screenshare_p2p_inner;
            CONTENT_TYPE_SCREENSHARE_SERVER : parse_zoom_screenshare_server_inner;
            CONTENT_TYPE_RTCP : parse_zoom_rtcp_inner;
            default : reject;
        }
    }

    state parse_zoom_content_p2p {
        transition select (hdr.zoom_type.zoom_type) {
            CONTENT_TYPE_VIDEO : parse_zoom_video_inner;
            CONTENT_TYPE_AUDIO : parse_zoom_audio_inner;
            CONTENT_TYPE_SCREENSHARE_P2P    : parse_zoom_screenshare_p2p_inner;
            CONTENT_TYPE_SCREENSHARE_SERVER : parse_zoom_screenshare_server_inner;
            CONTENT_TYPE_RTCP : parse_zoom_rtcp_inner;
            default : reject;
        }
    }

    state parse_zoom_video_inner {
        pkt.extract(hdr.zoom_video_inner);
        transition parse_rtp;
    }

    state parse_zoom_audio_inner {
        pkt.extract(hdr.zoom_audio_inner);
        transition parse_rtp;
    }

    state parse_zoom_screenshare_p2p_inner {
        pkt.extract(hdr.zoom_screenshare_p2p_inner);
        transition parse_rtp;
    }

    state parse_zoom_screenshare_server_inner {
        pkt.extract(hdr.zoom_screenshare_server_inner);
        transition parse_rtp;
    }

    state parse_zoom_rtcp_inner {
        pkt.extract(hdr.zoom_rtcp_inner);
        transition parse_rtcp;
    }

    state parse_rtp {
        pkt.extract(hdr.rtp);
        transition parse_rtp_extensions;
    }

    state parse_rtcp {
        pkt.extract(hdr.rtcp);
        transition accept;
    }

    state parse_rtp_extensions {
        pkt.extract(hdr.rtp_extension);
        pkt.extract(hdr.rtp_extension_one);
        pkt.extract(hdr.rtp_extension_two);
        pkt.extract(hdr.rtp_extension_three);
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    apply {

        if ( hdr.udp.isValid() && hdr.zoom_type.isValid() && hdr.zoom_outer.isValid() && hdr.zoom_inner_server.isValid() ) {

            if ( hdr.zoom_inner_server.zoom_type == CONTENT_TYPE_VIDEO ) {
                ig_tm_md.ucast_egress_port = 4;
            }
            else if ( hdr.zoom_inner_server.zoom_type == CONTENT_TYPE_AUDIO ) {
                ig_tm_md.ucast_egress_port = 5;
            }
        }
        
        // No need for egress processing, skip it and use empty controls for egress.
        ig_tm_md.bypass_egress = 1w1;
    }
}

// Empty egress parser/control blocks
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {}
}

control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;