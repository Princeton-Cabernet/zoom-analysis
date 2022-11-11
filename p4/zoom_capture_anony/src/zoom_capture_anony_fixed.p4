#include <core.p4>
#include <tna.p4>

#define BF_WIDTH 1
#define BF_CELLS 1 << 16
#define BF_IDX_WIDTH 16
#define DEFAULT_EGRESS_PORT 165

#define SALT_24 24w0x000000
#define SALT_32 32w0x00000000

// - typedefs:

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;
typedef bit<8> ip_protocol_t;
typedef bit<32> mask_t;

typedef bit<24> srcAddr_oui_t;
typedef bit<24> srcAddr_id_t;
typedef bit<24> dstAddr_oui_t;
typedef bit<24> dstAddr_id_t;

// - constants:

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const ether_type_t ETHERTYPE_ARP  = 16w0x0806;

const ip_protocol_t IP_PROTOCOL_ICMP = 1;
const ip_protocol_t IP_PROTOCOL_TCP  = 6;
const ip_protocol_t IP_PROTOCOL_UDP  = 17;

// - headers:

header ethernet_h {
    //mac_addr_t dst_addr;
    //mac_addr_t src_addr;
    //bit<16> ether_type;

    dstAddr_oui_t dst_addr_oui;
    dstAddr_id_t  dst_addr_id;
    srcAddr_oui_t src_addr_oui;
    srcAddr_id_t  src_addr_id;

    bit<16> ether_type;

}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header zoom_h {
    bit<8> is_zoom_pkt;
}

header vlan_tag_t {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> ether_type;
}

header arp_rarp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
}

header arp_rarp_ipv4_t {
    srcAddr_oui_t srcHwAddr_oui;
    srcAddr_id_t srcHwAddr_id;
    bit<32> srcProtoAddr;
    dstAddr_oui_t dstHwAddr_oui;
    dstAddr_id_t dstHwAddr_id;
    bit<32> dstProtoAddr;
}

struct header_t {
    ethernet_h ethernet;
    vlan_tag_t       vlan;
    arp_rarp_t       arp;
    arp_rarp_ipv4_t  arp_ipv4;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    zoom_h zoom;
}



// - metadata:

struct ig_metadata_t { 
    bit<1>  zoom_srv_dst_matched;
    bit<1>  zoom_srv_src_matched;
    bit<1>  stun_src_port_matched;
    bit<1>  stun_dst_port_matched;
    bit<1>  princeton_src_matched;
    bit<1>  princeton_dst_matched;
    bit<32> stun_peer_addr;
    bit<16> stun_peer_port;
    bit<1>  is_zoom_pkt;
}

struct eg_metadata_t { 
    bit<4> lets_hash_srcip;
    bit<4> lets_hash_dstip;
    bit<4> is_arp;
    bit<4> is_ipv4;
    bit<4> hashed_mac_srcAddr_oui;
    bit<4> hashed_mac_srcAddr_id;
    bit<4> hashed_mac_dstAddr_oui;
    bit<4> hashed_mac_dstAddr_id;
    dstAddr_oui_t dst_mac_mc_oui;
    srcAddr_oui_t src_mac_oui;
    srcAddr_id_t src_mac_id;
    dstAddr_oui_t dst_mac_oui;
    dstAddr_id_t dst_mac_id;
    srcAddr_oui_t src_hash_mac_oui;
    srcAddr_id_t src_hash_mac_id;
    dstAddr_oui_t dst_hash_mac_oui;
    dstAddr_id_t dst_hash_mac_id;
    bit<32> ipv4_srcip;
    bit<32> ipv4_dstip;
    bit<32> srcip_subnet_part;
    bit<32> srcip_hash_part32;
    bit<24> srcip_hash_part24;
    bit<16> srcip_hash_part16;
    bit<8> srcip_hash_part8;
    bit<32> srcip_hash_part;
    bit<32> dstip_subnet_part;
    bit<32> dstip_hash_part32;
    bit<24> dstip_hash_part24;
    bit<16> dstip_hash_part16;
    bit<8> dstip_hash_part8;
    bit<32> dstip_hash_part;
    bit<32> srcip_subnetmask;
    bit<32> dstip_subnetmask;
}





// - ingress parsers:

parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1: parse_resubmit;
            0: parse_port_metadata;
        }
    }

    state parse_resubmit {
        // parse resubmitted packet here
        transition reject;
    }
    
    state parse_port_metadata {
        pkt.advance(64); // tofino 1 port metadata size
        transition accept;
    }
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser; 
    
    state start {

        ig_md.zoom_srv_src_matched  = 0;
        ig_md.zoom_srv_dst_matched  = 0;
        ig_md.stun_src_port_matched = 0;
        ig_md.stun_dst_port_matched = 0;
        ig_md.princeton_src_matched = 0;
        ig_md.princeton_dst_matched = 0;
        ig_md.stun_peer_port        = 0;
        ig_md.stun_peer_addr        = 0;
        ig_md.is_zoom_pkt           = 0;

        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOL_TCP: parse_tcp;
            IP_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

// - ingress processing:

control SwitchIngress(
        inout header_t hdr,
        inout ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action nop() { }

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action set_egress_port(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action set_zoom_srv_src_matched(bit<1> matched) {
        ig_md.zoom_srv_src_matched = matched;
    }

    action set_zoom_srv_dst_matched(bit<1> matched) {
        ig_md.zoom_srv_dst_matched = matched;
    }

    action set_princeton_src_matched(bit<1> matched) {
        ig_md.princeton_src_matched = matched;
    }

    action set_princeton_dst_matched(bit<1> matched) {
        ig_md.princeton_dst_matched = matched;
    }

    action set_stun_src(bit<1> matched) {
        ig_md.stun_src_port_matched = matched;
        ig_md.stun_peer_addr = hdr.ipv4.dst_addr;
        ig_md.stun_peer_port = hdr.udp.dst_port;
    }

    action set_stun_dst(bit<1> matched) {
        ig_md.stun_dst_port_matched = matched;
        ig_md.stun_peer_addr = hdr.ipv4.src_addr;
        ig_md.stun_peer_port = hdr.udp.src_port;
    }

    table match_zoom_srv {

        const size = 256;
        
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
        }
        
        actions = { set_zoom_srv_src_matched; set_zoom_srv_dst_matched; nop; }
        
        const entries = {
            ( 32w0x03072300 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03158980 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03160b00 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03175d00 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03192980 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03192a00 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03193100 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03501480 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03601300 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03652080 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03653400 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03682280 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03787900 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x037fc280 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03d04800 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03d3f100 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03eb4500 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03eb5200 &&& 32w0xfffffe00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03eb4780 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03eb4880 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03eb4900 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x03eb6000 &&& 32w0xfffffe00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x04227d80 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x04234080 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x08058000 &&& 32w0xfffffe00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x0d340680 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x0d349200 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x129d5800 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x12cd5d80 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x32efca00 &&& 32w0xfffffe00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x32efcc00 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x343d6480 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x34519780 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x3451d700 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x34ca3ec0 &&& 32w0xffffffc0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x34d7a800 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x407d3e00 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x40d39000 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x41279800 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x45ae3900 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x45ae6c00 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x634f1400 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x6524a700 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x677aa600 &&& 32w0xfffffe00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x6f217300 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x6f21b500 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x736e9ac0 &&& 32w0xffffffc0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x737238c0 &&& 32w0xffffffc0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x73727300 &&& 32w0xffffffc0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x73728300 &&& 32w0xffffffc0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x781d9400 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x81970000 &&& 32w0xffffe000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x81972800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x81973000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x819f0000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x819fa000 &&& 32w0xffffe000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x819fd000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x823da400 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x86e00000 &&& 32w0xffff0000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x8cee8000 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x8ceee800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x90c30000 &&& 32w0xffff0000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x937c6000 &&& 32w0xffffe000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x95890000 &&& 32w0xffff8000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x96e6e000 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x98431400 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x98437600 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9843a800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9843b400 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9843b800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9843f000 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9846e000 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9c2d0000 &&& 32w0xffff8000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9e654000 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0x9e65b800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa0013880 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa1bdc700 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa1c78800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa20ce800 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa2ff2400 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa5fe5800 &&& 32w0xfffffe00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a1000 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a3000 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a3800 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a4800 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a4a00 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a5000 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a6000 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88a7400 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xa88af400 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xaa720000 &&& 32w0xffff0000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xade75000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc0cc0c00 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17a1000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17a2000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17ad000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17ae000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17af000 &&& 32w0xfffff000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17b0000 &&& 32w0xffffe000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17b2800 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17b8000 &&& 32w0xffffe000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17ba800 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc17bc000 &&& 32w0xffffe000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xc6fb8000 &&& 32w0xffff8000, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xcab1cf80 &&& 32w0xffffffe0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xcc506800 &&& 32w0xfffff800, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xcc8d1c00 &&& 32w0xfffffc00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xcfe28400 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xd109d300 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xd109d700 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xd5139000 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xd5139900 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xd5f48c00 &&& 32w0xffffff00, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xdd7a5840 &&& 32w0xffffffe0, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xdd7a5880 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xdd7a5980 &&& 32w0xffffff80, _ ): set_zoom_srv_src_matched(1);
            ( 32w0xdd7b8bc0 &&& 32w0xffffffe0, _ ): set_zoom_srv_src_matched(1);
            ( _, 32w0x03072300 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03158980 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03160b00 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03175d00 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03192980 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03192a00 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03193100 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03501480 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03601300 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03652080 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03653400 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03682280 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03787900 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x037fc280 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03d04800 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03d3f100 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03eb4500 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03eb5200 &&& 32w0xfffffe00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03eb4780 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03eb4880 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03eb4900 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x03eb6000 &&& 32w0xfffffe00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x04227d80 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x04234080 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x08058000 &&& 32w0xfffffe00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x0d340680 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x0d349200 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x129d5800 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x12cd5d80 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x32efca00 &&& 32w0xfffffe00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x32efcc00 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x343d6480 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x34519780 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x3451d700 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x34ca3ec0 &&& 32w0xffffffc0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x34d7a800 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x407d3e00 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x40d39000 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x41279800 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x45ae3900 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x45ae6c00 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x634f1400 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x6524a700 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x677aa600 &&& 32w0xfffffe00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x6f217300 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x6f21b500 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x736e9ac0 &&& 32w0xffffffc0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x737238c0 &&& 32w0xffffffc0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x73727300 &&& 32w0xffffffc0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x73728300 &&& 32w0xffffffc0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x781d9400 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x81970000 &&& 32w0xffffe000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x81972800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x81973000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x819f0000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x819fa000 &&& 32w0xffffe000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x819fd000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x823da400 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x86e00000 &&& 32w0xffff0000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x8cee8000 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x8ceee800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x90c30000 &&& 32w0xffff0000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x937c6000 &&& 32w0xffffe000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x95890000 &&& 32w0xffff8000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x96e6e000 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x98431400 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x98437600 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9843a800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9843b400 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9843b800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9843f000 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9846e000 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9c2d0000 &&& 32w0xffff8000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9e654000 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0x9e65b800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa0013880 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa1bdc700 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa1c78800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa20ce800 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa2ff2400 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa5fe5800 &&& 32w0xfffffe00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a1000 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a3000 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a3800 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a4800 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a4a00 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a5000 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a6000 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88a7400 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xa88af400 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xaa720000 &&& 32w0xffff0000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xade75000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc0cc0c00 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17a1000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17a2000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17ad000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17ae000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17af000 &&& 32w0xfffff000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17b0000 &&& 32w0xffffe000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17b2800 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17b8000 &&& 32w0xffffe000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17ba800 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc17bc000 &&& 32w0xffffe000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xc6fb8000 &&& 32w0xffff8000 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xcab1cf80 &&& 32w0xffffffe0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xcc506800 &&& 32w0xfffff800 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xcc8d1c00 &&& 32w0xfffffc00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xcfe28400 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xd109d300 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xd109d700 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xd5139000 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xd5139900 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xd5f48c00 &&& 32w0xffffff00 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xdd7a5840 &&& 32w0xffffffe0 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xdd7a5880 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xdd7a5980 &&& 32w0xffffff80 ): set_zoom_srv_dst_matched(1);
            ( _, 32w0xdd7b8bc0 &&& 32w0xffffffe0 ): set_zoom_srv_dst_matched(1);
        }

        const default_action = nop();
    }

    table match_stun {
        const size = 4;
        key = {
            ig_md.zoom_srv_src_matched: exact;
            ig_md.zoom_srv_dst_matched: exact;
            hdr.udp.src_port:           ternary;
            hdr.udp.dst_port:           ternary;
        }

        actions = { set_stun_src; set_stun_dst; nop; }

        const entries = {
            ( 1w1, 1w0, 16w3478, _): set_stun_src(1);
            ( 1w1, 1w0, 16w3479, _): set_stun_src(1);
            ( 1w0, 1w1, _, 16w3478): set_stun_dst(1);
            ( 1w0, 1w1, _, 16w3479): set_stun_dst(1);
        }

        const default_action = nop();
    }

    table match_princeton_src {

        const size = 10;
        
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
        }

        actions = { set_princeton_src_matched; nop; }

        const entries = {
            ( 32w0x80700000 &&& 32w0xffff0000, _): set_princeton_src_matched(1);
            ( 32w0x8cb40000 &&& 32w0xffff0000, _): set_princeton_src_matched(1);
            ( 32w0xcc993000 &&& 32w0xfffffe00, _): set_princeton_src_matched(1);
            ( 32w0x42b4b000 &&& 32w0xffffff00, _): set_princeton_src_matched(1);
            ( 32w0x42b4b100 &&& 32w0xffffff00, _): set_princeton_src_matched(1);
            ( 32w0x42b4b400 &&& 32w0xfffffc00, _): set_princeton_src_matched(1);
            ( 32w0xc0a80000 &&& 32w0xffff0000, _): set_princeton_src_matched(1);
            ( 32w0xac100000 &&& 32w0xfff00000, _): set_princeton_src_matched(1);
            ( 32w0x0a000000 &&& 32w0xff000000, _): set_princeton_src_matched(1);
        }


        const default_action = nop();
    }

    table match_princeton_dst {

        const size = 10;
        
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
        }

        actions = { set_princeton_dst_matched; nop; }

        const entries = {
            ( _, 32w0x80700000 &&& 32w0xffff0000): set_princeton_dst_matched(1);
            ( _, 32w0x8cb40000 &&& 32w0xffff0000): set_princeton_dst_matched(1);
            ( _, 32w0xcc993000 &&& 32w0xfffffe00): set_princeton_dst_matched(1);
            ( _, 32w0x42b4b000 &&& 32w0xffffff00): set_princeton_dst_matched(1);
            ( _, 32w0x42b4b100 &&& 32w0xffffff00): set_princeton_dst_matched(1);
            ( _, 32w0x42b4b400 &&& 32w0xfffffc00): set_princeton_dst_matched(1);
            ( _, 32w0xc0a80000 &&& 32w0xffff0000): set_princeton_dst_matched(1);
            ( _, 32w0xac100000 &&& 32w0xfff00000): set_princeton_dst_matched(1);
            ( _, 32w0x0a000000 &&& 32w0xff000000): set_princeton_dst_matched(1);
        }



        const default_action = nop();
    }

    table send_pkt {
        const size = 2;
        key = { ig_md.is_zoom_pkt: exact; }
        actions = { set_egress_port; drop; }
        const default_action = set_egress_port(DEFAULT_EGRESS_PORT); 
    }

    // hash function for bloom filter -> 4b hash
    Hash<bit<BF_IDX_WIDTH>>(HashAlgorithm_t.CRC16) stun_hash;
    Hash<bit<BF_IDX_WIDTH>>(HashAlgorithm_t.CRC16) src_hash;
    Hash<bit<BF_IDX_WIDTH>>(HashAlgorithm_t.CRC16) dst_hash;
    
    // register with 4b index and 32b value
    Register<bit<BF_WIDTH>, bit<BF_IDX_WIDTH>>(BF_CELLS, 0) p2p_srcs;
    Register<bit<BF_WIDTH>, bit<BF_IDX_WIDTH>>(BF_CELLS, 0) p2p_dsts;

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<BF_WIDTH>, bit<BF_IDX_WIDTH>, bit<BF_WIDTH>>(p2p_srcs) p2p_srcs_set = {
        void apply(inout bit<BF_WIDTH> val, out bit<BF_WIDTH> ret) {
            val = 1;
            ret = 1;
        }
    };

    RegisterAction<bit<BF_WIDTH>, bit<BF_IDX_WIDTH>, bit<BF_WIDTH>>(p2p_srcs) p2p_srcs_get = {
        void apply(inout bit<BF_WIDTH> val, out bit<BF_WIDTH> ret) {
            ret = val;
        }
    };

    RegisterAction<bit<BF_WIDTH>, bit<BF_IDX_WIDTH>, bit<BF_WIDTH>>(p2p_dsts) p2p_dsts_set = {
        void apply(inout bit<BF_WIDTH> val, out bit<BF_WIDTH> ret) {
            val = 1;
            ret = 1;
        }
    };

    RegisterAction<bit<BF_WIDTH>, bit<BF_IDX_WIDTH>, bit<BF_WIDTH>>(p2p_dsts) p2p_dsts_get = {
        void apply(inout bit<BF_WIDTH> val, out bit<BF_WIDTH> ret) {
            ret = val;
        }
    };

    Counter<bit<32>, bit<1>>(1, CounterType_t.PACKETS_AND_BYTES) all_pkts_counter;

    Counter<bit<32>, bit<1>>(1, CounterType_t.PACKETS_AND_BYTES) zoom_pkts_counter;

    apply {

        all_pkts_counter.count(0);

        match_zoom_srv.apply();
        
        if (ig_md.zoom_srv_src_matched == 1
            || ig_md.zoom_srv_dst_matched == 1) {

            match_stun.apply();

            if (ig_md.stun_src_port_matched == 1
                || ig_md.stun_dst_port_matched == 1) {
            
                bit<BF_IDX_WIDTH> idx = stun_hash.get({
                    ig_md.stun_peer_addr, ig_md.stun_peer_port
                });

                p2p_srcs_set.execute(idx);
                p2p_dsts_set.execute(idx);
            }

            ig_md.is_zoom_pkt = 1;
            
        } else {

            if (hdr.udp.isValid()) {

                match_princeton_src.apply();
                match_princeton_dst.apply();

                bit<BF_IDX_WIDTH> src_idx = src_hash.get({
                    hdr.ipv4.src_addr, hdr.udp.src_port
                });

                bit<BF_IDX_WIDTH> dst_idx = dst_hash.get({
                    hdr.ipv4.dst_addr, hdr.udp.dst_port
                });

                bit<BF_WIDTH> p2p_src_matched = 0;
                bit<BF_WIDTH> p2p_dst_matched = 0;

                if (ig_md.princeton_src_matched == 1) {

                    p2p_src_matched = p2p_srcs_get.execute(src_idx);

                } else if (ig_md.princeton_dst_matched == 1) {

                    p2p_dst_matched = p2p_dsts_get.execute(dst_idx);

                } else if (ig_md.princeton_src_matched == 1
                    && ig_md.princeton_dst_matched == 1) {

                    p2p_src_matched = p2p_srcs_get.execute(src_idx);
                    p2p_dst_matched = p2p_dsts_get.execute(dst_idx);
                }

                if (p2p_src_matched == 1 || p2p_dst_matched == 1) {
                    ig_md.is_zoom_pkt = 1;
                }
            }
        }

        if (ig_md.is_zoom_pkt == 1) {
            hdr.zoom.setValid();
            hdr.zoom.is_zoom_pkt = 1;
            zoom_pkts_counter.count(0);
            send_pkt.apply();
        }
    }
}

// - ingress deparsing:

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

// - empty blocks for egress:

parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
//    state start {
//        pkt.extract(eg_intr_md);
//        transition accept;
//    }

    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);

        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN : parse_vlan;
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
//        meta.is_ipv4 = (bit<4>) 1;
//        meta.ipv4_srcip = hdr.ipv4.srcAddr;
//        meta.ipv4_dstip = hdr.ipv4.dstAddr;
//        meta.srcip_subnet_part = hdr.ipv4.srcAddr;
//        meta.dstip_subnet_part = hdr.ipv4.dstAddr;
    
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOL_TCP : parse_tcp;
            IP_PROTOCOL_UDP : parse_udp;
            default: accept;
        }
    }
    
    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition select(hdr.vlan.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default: accept;
        }
    }
    
    state parse_arp {
        pkt.extract(hdr.arp);
        transition select(hdr.arp.protoType) {
            ETHERTYPE_IPV4 : parse_arp_rarp_ipv4;
            default : accept;
        }
    }
    
    state parse_arp_rarp_ipv4 {
        pkt.extract(hdr.arp_ipv4);
        eg_md.is_arp = (bit<4>) 1;
        eg_md.ipv4_srcip = hdr.arp_ipv4.srcProtoAddr;
        eg_md.ipv4_dstip =  hdr.arp_ipv4.dstProtoAddr;
        eg_md.srcip_subnet_part = hdr.arp_ipv4.srcProtoAddr;
        eg_md.dstip_subnet_part = hdr.arp_ipv4.dstProtoAddr;
        transition accept;
    }
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        //transition accept;
        transition parse_zoom_hdr;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        //transition accept;
        transition parse_zoom_hdr;
    }

    state parse_zoom_hdr {
        pkt.extract(hdr.zoom);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {

    apply { 
        pkt.emit(hdr);
    }
}

control SwitchEgress(
        inout header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {


    /************ ACTIONS ************/
    action nop_action() {
    }
 
    action multicast_mac_catch_action() {
        eg_md.dst_mac_mc_oui = hdr.ethernet.dst_addr_oui & 0x110000;
    }
    
    /***************************************************************
     * Prepare hashing by dividing subnet part and hash part
     * by masking.  SRC IP.
     * 
     * mask1:    subnet mask (e.g., 255.255.255.0)
     * mask2:    wildcard part mask (e.g., 0.0.0.255)
     */
    action prepare_srcip_hash_action(mask_t mask1, mask_t mask2) {


        eg_md.srcip_subnet_part = hdr.ipv4.src_addr & mask1;
        eg_md.srcip_hash_part = hdr.ipv4.src_addr & mask2;
        eg_md.lets_hash_srcip = 1;

        eg_md.srcip_subnetmask =  mask1;
    }
    
    /***************************************************************
     * Prepare hashing by dividing subnet part and hash part
     * by masking. DST IP. 
     * 
     * mask1:    subnet mask (e.g., 255.255.255.0)
     * mask2:    wildcard part mask (e.g., 0.0.0.255)
     */
    action prepare_dstip_hash_action(mask_t mask1,mask_t mask2) {

        eg_md.dstip_subnet_part = hdr.ipv4.dst_addr & mask1;
        eg_md.dstip_hash_part = hdr.ipv4.dst_addr & mask2;
        eg_md.lets_hash_dstip = 1;
    
        eg_md.dstip_subnetmask = mask1;
    }
    
    action hash_mac_src_id_action() {

        // hash(hdr.ethernet.src_addr_id, HashAlgorithm_t.CRC32, 32w0, {eg_md.src_mac_id}, 32w24);
        hdr.ethernet.src_addr_id = (bit<24>) eg_md.src_hash_mac_id;
        eg_md.hashed_mac_srcAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_src_oui_action() {
        //hash(hdr.ethernet.src_addr_oui, HashAlgorithm.crc32, 32w0, {eg_md.src_mac_oui}, 32w24);
        //hdr.ethernet.src_addr_oui= (bit<24>) eg_md.crc32.get(eg_md.src_mac_oui);
        hdr.ethernet.src_addr_oui= (bit<24>) eg_md.src_hash_mac_oui;
        eg_md.hashed_mac_srcAddr_oui = (bit<4>) 1;
    }
    
    action hash_arp_mac_src_id_action() {
        hdr.arp_ipv4.srcHwAddr_id = hdr.ethernet.src_addr_id;
    }
    
    action hash_arp_mac_src_oui_action() {
        hdr.arp_ipv4.srcHwAddr_oui = hdr.ethernet.src_addr_oui;
    }
    
    action hash_mac_dst_id_action() {
        //hash(hdr.ethernet.dst_addr_id, HashAlgorithm.crc32, 32w0, {eg_md.dst_mac_id}, 32w24);
        //hdr.ethernet.dst_addr_id = (bit<24>) eg_md.crc32.get(eg_md.dst_mac_id);
        hdr.ethernet.dst_addr_id = (bit<24>) eg_md.dst_hash_mac_id;
        eg_md.hashed_mac_dstAddr_id = (bit<4>) 1;
    }
    
    action hash_mac_dst_oui_action() {
        //hash(hdr.ethernet.dst_addr_oui, HashAlgorithm.crc32, 32w0, {eg_md.dst_mac_oui}, 32w24);
        //hdr.ethernet.dst_addr_oui = (bit<24>) eg_md.crc32.get(eg_md.dst_mac_oui);
        hdr.ethernet.dst_addr_oui = (bit<24>) eg_md.dst_hash_mac_oui;
        eg_md.hashed_mac_dstAddr_oui = (bit<4>) 1;
    }
    
    action hash_arp_mac_dst_id_action() {
        hdr.arp_ipv4.dstHwAddr_id = hdr.ethernet.dst_addr_id;
    }
    
    action hash_arp_mac_dst_oui_action() {
        hdr.arp_ipv4.dstHwAddr_oui = hdr.ethernet.dst_addr_oui;
    }
    
    action hash_and_modify_src0_action() { 
        //hash(eg_md.srcip_hash_part, HashAlgorithm.crc32, 32w0, {eg_md.srcip_hash_part}, 32w32);
        //eg_md.srcip_hash_part = (bit<32>) eg_md.crc32.get(eg_md.srcip_hash_part);
        eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part32;
    }
    action hash_and_modify_src8_action() { 
        //hash(eg_md.srcip_hash_part, HashAlgorithm.crc32_custom, 32w0, {eg_md.srcip_hash_part}, 32w24);
        //eg_md.srcip_hash_part = (bit<24>) eg_md.crc32.get(eg_md.srcip_hash_part);
        eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part24;
    }
    action hash_and_modify_src16_action() { 
        //hash(eg_md.srcip_hash_part, HashAlgorithm.crc16, 32w0, {eg_md.srcip_hash_part}, 32w16);
        //eg_md.srcip_hash_part = (bit<16>) eg_md.crc32.get(eg_md.srcip_hash_part);
        eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part16;
    }
    action hash_and_modify_src24_action() { 
        //hash(eg_md.srcip_hash_part, HashAlgorithm.crc16_custom, 32w0, {eg_md.srcip_hash_part}, 32w8);
        //eg_md.srcip_hash_part = (bit<8>) eg_md.crc32.get(eg_md.srcip_hash_part);
        eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part8;
    }
    action hash_and_modify_dst0_action() { 
        //hash(eg_md.dstip_hash_part, HashAlgorithm.crc32, 32w0, {eg_md.dstip_hash_part}, 32w32);
        //eg_md.dstip_hash_part = (bit<32>) eg_md.crc32.get(eg_md.dstip_hash_part);
        eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part32;
    }
    action hash_and_modify_dst8_action() { 
        //hash(eg_md.dstip_hash_part, HashAlgorithm.crc32_custom, 32w0, {eg_md.dstip_hash_part}, 32w24);
        //eg_md.dstip_hash_part = (bit<24>) eg_md.crc32.get(eg_md.dstip_hash_part);
        eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part24;
    }
    action hash_and_modify_dst16_action() { 
        //hash(eg_md.dstip_hash_part, HashAlgorithm.crc16, 32w0, {eg_md.dstip_hash_part}, 32w16);
        //eg_md.dstip_hash_part = (bit<16>) eg_md.crc32.get(eg_md.dstip_hash_part);
        eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part16;
    }
    action hash_and_modify_dst24_action() { 
        //hash(eg_md.dstip_hash_part, HashAlgorithm.crc16_custom, 32w0, {eg_md.dstip_hash_part}, 32w8);
        //eg_md.dstip_hash_part = (bit<8>) eg_md.crc32.get(eg_md.dstip_hash_part);
        eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part8;
    }
    
    action ip_overwrite_action() { 
        hdr.ipv4.src_addr = eg_md.srcip_subnet_part | eg_md.srcip_hash_part;
        hdr.ipv4.dst_addr = eg_md.dstip_subnet_part | eg_md.dstip_hash_part;

    }
    
    action arp_ip_overwrite_action() { 
        hdr.arp_ipv4.srcProtoAddr = eg_md.srcip_subnet_part | eg_md.srcip_hash_part;
        hdr.arp_ipv4.dstProtoAddr = eg_md.dstip_subnet_part | eg_md.dstip_hash_part;
    }


    /************ CONTROL ************/
    table anony_mac_src_id_tb {
        key =  {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions  = {
            hash_mac_src_id_action;
            nop_action;
        }

        const entries = {
            ( 1 ): hash_mac_src_id_action();
        }
    }
    
    table anony_mac_src_oui_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions =  {
            hash_mac_src_oui_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_src_id_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_arp_mac_src_id_action;
            nop_action;
        }
        const entries = {
            ( 1 ): hash_arp_mac_src_id_action();
        }
    }
    
    table anony_arp_mac_src_oui_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions  = {
            hash_arp_mac_src_oui_action;
            nop_action;
        }
    }
    
    table anony_mac_dst_id_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_mac_dst_id_action;
            nop_action;
        }
        const entries = {
            ( 1 ): hash_mac_dst_id_action();
        }
    }
    
    table anony_mac_dst_oui_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions =  {
            hash_mac_dst_oui_action;
            nop_action;
        }
    }
    
    table anony_arp_mac_dst_id_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_arp_mac_dst_id_action;
            nop_action;
        }
        const entries = {
            ( 1 ): hash_arp_mac_dst_id_action();
        }
    }
    
    table anony_arp_mac_dst_oui_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_arp_mac_dst_oui_action;
            nop_action;
        }
    }
    
    table anony_srcip_tb {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
        }
        actions =  {
            prepare_srcip_hash_action;
            nop_action;
        }
        const entries = {
            ( 32w0x0a080000 &&& 32w0xffff0000, _ ): prepare_srcip_hash_action(0xffff0000,0x0000ffff);
            ( 32w0x0a090000 &&& 32w0xffff0000, _ ): prepare_srcip_hash_action(0xffff0000,0x0000ffff);
        }
    }
    
    table anony_dstip_tb {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
        }
    
        actions = {
            prepare_dstip_hash_action;
            nop_action;
        }
        const entries = {
            ( _ , 32w0x0a080000 &&& 32w0xffff0000 ): prepare_dstip_hash_action(0xffff0000,0x0000ffff);
            ( _ , 32w0x0a090000 &&& 32w0xffff0000 ): prepare_dstip_hash_action(0xffff0000,0x0000ffff);
        }
    }
    
    table hashing_src0_tb {
        key = {
             hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_src0_action;
            nop_action;
        }
    }
    
    table hashing_src8_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_src8_action;
            nop_action;
        }
    }
    
    table hashing_src16_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_src16_action;
            nop_action;
        }
    }
    
    table hashing_src24_tb {
        key= {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_src24_action;
            nop_action;
        }
    }
    
    table hashing_dst0_tb {
        key =  {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_dst0_action;
            nop_action;
        }
    }
    
    table hashing_dst8_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_dst8_action;
            nop_action;
        }
    }
    table hashing_dst16_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_dst16_action;
            nop_action;
        }
    }
    table hashing_dst24_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            hash_and_modify_dst24_action;
            nop_action;
        }
    }
    
    table multicast_mac_catch_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            multicast_mac_catch_action;
        }
        const entries = {
            ( 1 ): multicast_mac_catch_action();
        }
    }
    
    table arp_ip_overwrite_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            arp_ip_overwrite_action;
        }
        const entries = {
            ( 1 ): arp_ip_overwrite_action();
        }
    }
    
    table ipv4_ip_overwite_tb {
        key = {
            hdr.zoom.is_zoom_pkt : exact;
        }
        actions = {
            ip_overwrite_action;
        }
        const entries = {
            ( 1 ): ip_overwrite_action();
        }
    }

    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32_src_mac_id;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32_dst_mac_id;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) crc32d;
    Hash<bit<32>>(HashAlgorithm_t.CRC16) crc16;
    Hash<bit<32>>(HashAlgorithm_t.CRC16) crc16d;
    
    apply {


        eg_md.lets_hash_srcip = 0;
        eg_md.lets_hash_dstip = 0;

        // Needed for catching multicast packets
        //  based on DST MAC address (starts with 01:xx:xx:xx:xx:xx)
        multicast_mac_catch_tb.apply();

        eg_md.src_hash_mac_id = (bit<24>) crc32_src_mac_id.get(hdr.ethernet.src_addr_id + SALT_24);
  
       // Anonymize SRC MAC
        anony_mac_src_id_tb.apply();

        // Only anonymize if DST MAC indicates
        //  that it's not a broadcast or multicast packet.
        if (hdr.ethernet.dst_addr_oui!=0xffffff) {
            if (hdr.ethernet.dst_addr_id!=0xffffff) {
                if (eg_md.dst_mac_mc_oui!=0x010000) {

                    eg_md.dst_hash_mac_id  = (bit<24>) crc32_dst_mac_id.get(hdr.ethernet.dst_addr_id + SALT_24);
                    anony_mac_dst_id_tb.apply();
                }
            }
        }

        // If ARP reply and DST MAC is hashed,
        //   hash DST MAC in ARP packet too.
        if (hdr.arp.opcode == 2) {
            if (eg_md.hashed_mac_dstAddr_id == 1) {
                anony_arp_mac_dst_id_tb.apply();
            }
            if (eg_md.hashed_mac_dstAddr_oui == 1) {
                anony_arp_mac_dst_oui_tb.apply();
            }
        }

        // If SRC MAC is hashed,
        //   hash SRC MAC in ARP packet too.
        if (eg_md.hashed_mac_srcAddr_id == 1) {
            anony_arp_mac_src_id_tb.apply();
        }
        if (eg_md.hashed_mac_srcAddr_oui == 1) {
            anony_arp_mac_src_oui_tb.apply();
        }

        // Anoymize IPv4 SRC address (prep step)
        anony_srcip_tb.apply();

        //eg_md.srcip_hash_part32 = (bit<32>) crc32.get(eg_md.srcip_hash_part);
        //eg_md.srcip_hash_part24 = (bit<24>) crc32.get(eg_md.srcip_hash_part);
        //eg_md.srcip_hash_part24 = (bit<24>) eg_md.srcip_hash_part32;

        //eg_md.srcip_hash_part16 = (bit<16>) crc16.get(eg_md.srcip_hash_part);
        //eg_md.srcip_hash_part8 = (bit<8>) eg_md.srcip_hash_part16;

        if (eg_md.lets_hash_srcip == 0) {
            eg_md.srcip_subnet_part = hdr.ipv4.src_addr & 0xffffffff;
            eg_md.srcip_hash_part = hdr.ipv4.src_addr & 0x00000000;
        }
        else {
            if (eg_md.srcip_subnetmask == 0x0) {
                eg_md.srcip_hash_part = crc32.get(eg_md.srcip_hash_part + SALT_32);
                //hashing_src0_tb.apply();
            }
            else if (eg_md.srcip_subnetmask == 0xff000000) {
                eg_md.srcip_hash_part24 = (bit<24>) crc32.get(eg_md.srcip_hash_part + SALT_32);
                eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part24;
                //hashing_src8_tb.apply();
            }
            else if (eg_md.srcip_subnetmask == 0xffff0000) {
                eg_md.srcip_hash_part16 = (bit<16>) crc16.get(eg_md.srcip_hash_part + SALT_32);
                eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part16;
                //hashing_src16_tb.apply();
            }
            else {
                eg_md.srcip_hash_part8 = (bit<8>) crc16.get(eg_md.srcip_hash_part + SALT_32);
                eg_md.srcip_hash_part = (bit<32>) eg_md.srcip_hash_part8;
                //hashing_src24_tb.apply();
            }
        }

        // Anoymize IPv4 DST address (prep step)
        anony_dstip_tb.apply();

        //eg_md.dstip_hash_part32 = (bit<32>) crc32.get(eg_md.dstip_hash_part);
        //eg_md.dstip_hash_part24 = (bit<24>) crc32.get(eg_md.dstip_hash_part);
        //eg_md.dstip_hash_part16 = (bit<16>) crc16.get(eg_md.dstip_hash_part);
        //eg_md.dstip_hash_part8 = (bit<8>) crc16.get(eg_md.dstip_hash_part);

        if (eg_md.lets_hash_dstip == 0) {
            eg_md.dstip_subnet_part = hdr.ipv4.dst_addr & 0xffffffff;
            eg_md.dstip_hash_part = hdr.ipv4.dst_addr & 0x00000000;
        }
        else {
 
            if (eg_md.dstip_subnetmask == 0x0) {
                eg_md.dstip_hash_part = crc32d.get(eg_md.dstip_hash_part + SALT_32);
                //hashing_dst0_tb.apply();
            }
            else if (eg_md.dstip_subnetmask == 0xff000000) {
                eg_md.dstip_hash_part24 = (bit<24>) crc32d.get(eg_md.dstip_hash_part + SALT_32);
                eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part24;
                //hashing_dst8_tb.apply();
            }
            else if (eg_md.dstip_subnetmask == 0xffff0000) {
                eg_md.dstip_hash_part16 = (bit<16>) crc16d.get(eg_md.dstip_hash_part + SALT_32);
                eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part16;
                //hashing_dst16_tb.apply();
            }
            else {
                eg_md.dstip_hash_part8 = (bit<8>) crc16d.get(eg_md.dstip_hash_part + SALT_32);
                eg_md.dstip_hash_part = (bit<32>) eg_md.dstip_hash_part8;
                //hashing_dst24_tb.apply();
            }
        }

        // If ARP packet, and should anonymize IPv4, 
        //  anonymize IP address in ARP packet.
        if (eg_md.is_arp == 1) {
            arp_ip_overwrite_tb.apply();
        }

        // Actual IPv4 address anonymization step
        if (hdr.ipv4.isValid()) {
        //if (eg_md.is_ipv4 == 1) {
            ipv4_ip_overwite_tb.apply();
        }

        // remove zoom header
        hdr.zoom.setInvalid();
    }
}

// - switch pipeline:

Pipeline(SwitchIngressParser(), SwitchIngress(), SwitchIngressDeparser(),
         SwitchEgressParser(), SwitchEgress(), SwitchEgressDeparser()) pipe;

Switch(pipe) main;
