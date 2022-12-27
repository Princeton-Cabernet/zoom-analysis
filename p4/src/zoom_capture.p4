#include <core.p4>
#include <tna.p4>

#define BF_WIDTH 1
#define BF_CELLS 1 << 16
#define BF_IDX_WIDTH 16
#define DEFAULT_EGRESS_PORT 4
#define TIME_DUR_CUTOFF 0x9D2922A // Cut-off equivalent to ~3 hrs. (~ 3*60*60*10e9 >> 16)
// #define TIME_DUR_CUTOFF 0x45D964 // Cut-off equivalent to ~5 mins.

// Typedefs

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> ipv4_addr_t;
typedef bit<8> ip_protocol_t;
typedef bit<32> mask_t;

typedef bit<24> srcAddr_oui_t;
typedef bit<24> srcAddr_id_t;
typedef bit<24> dstAddr_oui_t;
typedef bit<24> dstAddr_id_t;

// Constants

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const ether_type_t ETHERTYPE_ARP  = 16w0x0806;

const ip_protocol_t IP_PROTOCOL_ICMP = 1;
const ip_protocol_t IP_PROTOCOL_TCP  = 6;
const ip_protocol_t IP_PROTOCOL_UDP  = 17;

// Headers

header ethernet_h {
    dstAddr_oui_t dst_addr_oui;
    dstAddr_id_t  dst_addr_id;
    srcAddr_oui_t src_addr_oui;
    srcAddr_id_t  src_addr_id;
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

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h  tcp;
    udp_h  udp;
}

struct empty_header_t { }

struct eg_metadata_t { }

// Metadata

struct ig_metadata_t {
    bit<32> all_pkts_count;
    bit<32> zoom_pkts_count;
    bit<32> ingress_tstamp;
    bit<1>  zoom_srv_dst_matched;
    bit<1>  zoom_srv_src_matched;
    bit<1>  stun_src_port_matched;
    bit<1>  stun_dst_port_matched;
    bit<1>  campus_src_matched;
    bit<1>  campus_dst_matched;
    bit<8>  non_srv_port_matched;
    bit<32> stun_peer_addr;
    bit<16> stun_peer_port;
    bit<1>  is_zoom_pkt;

    bit<16> status_code;
}

// Ingress parsers:

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

        ig_md.all_pkts_count        = 0;
        ig_md.zoom_pkts_count       = 0;
        ig_md.ingress_tstamp        = 0;
        ig_md.zoom_srv_src_matched  = 0;
        ig_md.zoom_srv_dst_matched  = 0;
        ig_md.stun_src_port_matched = 0;
        ig_md.stun_dst_port_matched = 0;
        ig_md.campus_src_matched    = 0;
        ig_md.campus_dst_matched    = 0;
        ig_md.non_srv_port_matched  = 0;
        ig_md.stun_peer_port        = 0;
        ig_md.stun_peer_addr        = 0;
        ig_md.is_zoom_pkt           = 0;

        ig_md.status_code           = 0;

        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
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

    action set_zoom_srv_src_matched() {
        ig_md.zoom_srv_src_matched = 1;
    }

    action set_zoom_srv_dst_matched() {
        ig_md.zoom_srv_dst_matched = 1;
    }

    action set_campus_src_matched() {
        ig_md.campus_src_matched = 1;
    }

    action set_campus_dst_matched() {
        ig_md.campus_dst_matched = 1;
    }

    action set_stun_src() {
        ig_md.stun_src_port_matched = 1;
        ig_md.stun_peer_addr = hdr.ipv4.dst_addr;
        ig_md.stun_peer_port = hdr.udp.dst_port;
    }

    action set_stun_dst() {
        ig_md.stun_dst_port_matched = 1;
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
            // The file below contains an enumeration of Zoom IP prefixes as match-action table entries.
            // Please update this file if the list changes. Currently, this list is available here on the Zoom website:
            // https://support.zoom.us/hc/en-us/articles/201362683-Zoom-network-firewall-or-proxy-server-settings
             #include "entries_match_zoom_server.p4inc"
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
            ( 1w1, 1w0, 16w3478, _): set_stun_src();
            ( 1w1, 1w0, 16w3479, _): set_stun_src();
            ( 1w0, 1w1, _, 16w3478): set_stun_dst();
            ( 1w0, 1w1, _, 16w3479): set_stun_dst();
        }

        const default_action = nop();
    }

    table match_campus_src {

        const size = 10;
        
        key = {
            hdr.ipv4.src_addr: ternary;
        }

        actions = { set_campus_src_matched; nop; }

        const entries = {
            // These rules are specific to the Princeton campus; please replace with IP prefixes of your own network
            ( 32w0x80700000 &&& 32w0xffff0000 ): set_campus_src_matched();
            ( 32w0x8cb40000 &&& 32w0xffff0000 ): set_campus_src_matched();
            ( 32w0xcc993000 &&& 32w0xfffffe00 ): set_campus_src_matched();
            ( 32w0x42b4b000 &&& 32w0xffffff00 ): set_campus_src_matched();
            ( 32w0x42b4b100 &&& 32w0xffffff00 ): set_campus_src_matched();
            ( 32w0x42b4b400 &&& 32w0xfffffc00 ): set_campus_src_matched();
            ( 32w0xc0a80000 &&& 32w0xffff0000 ): set_campus_src_matched();
            ( 32w0xac100000 &&& 32w0xfff00000 ): set_campus_src_matched();
            ( 32w0x0a000000 &&& 32w0xff000000 ): set_campus_src_matched();
        }

        const default_action = nop();
    }

    table match_campus_dst {

        const size = 10;
        
        key = {
            hdr.ipv4.dst_addr: ternary;
        }

        actions = { set_campus_dst_matched; nop; }

        const entries = {
            // These rules are specific to the Princeton campus; please replace with IP prefixes of your own network
            ( 32w0x80700000 &&& 32w0xffff0000 ): set_campus_dst_matched();
            ( 32w0x8cb40000 &&& 32w0xffff0000 ): set_campus_dst_matched();
            ( 32w0xcc993000 &&& 32w0xfffffe00 ): set_campus_dst_matched();
            ( 32w0x42b4b000 &&& 32w0xffffff00 ): set_campus_dst_matched();
            ( 32w0x42b4b100 &&& 32w0xffffff00 ): set_campus_dst_matched();
            ( 32w0x42b4b400 &&& 32w0xfffffc00 ): set_campus_dst_matched();
            ( 32w0xc0a80000 &&& 32w0xffff0000 ): set_campus_dst_matched();
            ( 32w0xac100000 &&& 32w0xfff00000 ): set_campus_dst_matched();
            ( 32w0x0a000000 &&& 32w0xff000000 ): set_campus_dst_matched();
        }

        const default_action = nop();
    }


    // Registers as counters
    Register<bit<32>, bit<1>>(1) all_pkts_counter;
    Register<bit<32>, bit<1>>(1) zoom_pkts_counter;

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<1>, bit<32>>(all_pkts_counter) all_pkts_incr_and_read = {
        void apply(inout bit<32> val, out bit<32> ret) {
            val = val + 1;
            ret = val;
        } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(zoom_pkts_counter) zoom_pkts_incr_and_read = {
        void apply(inout bit<32> val, out bit<32> ret) {
            val = val + 1;
            ret = val;
        } };

    
    // Registers with 16-bit index (holds 1/3rd key) and 32-bit value (timestamp)
    
    // P2P Source: Registers
    Register<bit<32>, bit<16>>(65536) p2p_srcs_stage0_reg;
    Register<bit<32>, bit<16>>(65536) p2p_srcs_stage1_reg;
    Register<bit<32>, bit<16>>(65536) p2p_srcs_stage2_reg;

    // P2P Destination: Registers
    Register<bit<32>, bit<16>>(65536) p2p_dsts_stage0_reg;
    Register<bit<32>, bit<16>>(65536) p2p_dsts_stage1_reg;
    Register<bit<32>, bit<16>>(65536) p2p_dsts_stage2_reg;


    // P2P Source: Stage 0

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_srcs_stage0_reg) p2p_srcs_stage0_set = {
        void apply(inout bit<32> val, out bit<1> ret) {
            if (ig_md.ingress_tstamp > 0) {
                val = ig_md.ingress_tstamp;
            } else {
                val = 1;
            }
            ret = 1;
        } };

    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_srcs_stage0_reg) p2p_srcs_stage0_update_or_reset = {
        void apply(inout bit<32> val, out bit<1> present) {
            // Determine if current value is stale; also works if value == 0
            if ((val > 0) && (ig_md.ingress_tstamp - val > TIME_DUR_CUTOFF)) {
                val = 0; present = 0;
            } else if (val > 0) {
                val = ig_md.ingress_tstamp; present = 1;
            } } };

    // P2P Source: Stage 1

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_srcs_stage1_reg) p2p_srcs_stage1_set = {
        void apply(inout bit<32> val, out bit<1> ret) {
            if (ig_md.ingress_tstamp > 0) {
                val = ig_md.ingress_tstamp;
            } else {
                val = 1;
            }
            ret = 1;
        } };

    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_srcs_stage1_reg) p2p_srcs_stage1_update_or_reset = {
        void apply(inout bit<32> val, out bit<1> present) {
            // Determine if current value is stale; also works if value == 0
            if ((val > 0) && (ig_md.ingress_tstamp - val > TIME_DUR_CUTOFF)) {
                val = 0; present = 0;
            } else if (val > 0) {
                val = ig_md.ingress_tstamp; present = 1;
            } } };

    // P2P Source: Stage 2

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_srcs_stage2_reg) p2p_srcs_stage2_set = {
        void apply(inout bit<32> val, out bit<1> ret) {
            if (ig_md.ingress_tstamp > 0) {
                val = ig_md.ingress_tstamp;
            } else {
                val = 1;
            }
            ret = 1;
        } };

    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_srcs_stage2_reg) p2p_srcs_stage2_update_or_reset = {
        void apply(inout bit<32> val, out bit<1> present) {
            // Determine if current value is stale; also works if value == 0
            if ((val > 0) && (ig_md.ingress_tstamp - val > TIME_DUR_CUTOFF)) {
                val = 0; present = 0;
            } else if (val > 0) {
                val = ig_md.ingress_tstamp; present = 1;
            } } };


    // P2P Destination: Stage 0

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_dsts_stage0_reg) p2p_dsts_stage0_set = {
        void apply(inout bit<32> val, out bit<1> ret) {
            if (ig_md.ingress_tstamp > 0) {
                val = ig_md.ingress_tstamp;
            } else {
                val = 1;
            }
            ret = 1;
        } };

    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_dsts_stage0_reg) p2p_dsts_stage0_update_or_reset = {
        void apply(inout bit<32> val, out bit<1> present) {
            // Determine if current value is stale; also works if value == 0
            if ((val > 0) && (ig_md.ingress_tstamp - val > TIME_DUR_CUTOFF)) {
                val = 0; present = 0;
            } else if (val > 0) {
                val = ig_md.ingress_tstamp; present = 1;
            } } };
    
    // P2P Destination: Stage 1

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_dsts_stage1_reg) p2p_dsts_stage1_set = {
        void apply(inout bit<32> val, out bit<1> ret) {
            if (ig_md.ingress_tstamp > 0) {
                val = ig_md.ingress_tstamp;
            } else {
                val = 1;
            }
            ret = 1;
        } };

    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_dsts_stage1_reg) p2p_dsts_stage1_update_or_reset = {
        void apply(inout bit<32> val, out bit<1> present) {
            // Determine if current value is stale; also works if value == 0
            if ((val > 0) && (ig_md.ingress_tstamp - val > TIME_DUR_CUTOFF)) {
                val = 0; present = 0;
            } else if (val > 0) {
                val = ig_md.ingress_tstamp; present = 1;
            } } };

    // P2P Destination: Stage 2

    // RegisterAction<ValueType, IndexType, ReturnType>
    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_dsts_stage2_reg) p2p_dsts_stage2_set = {
        void apply(inout bit<32> val, out bit<1> ret) {
            if (ig_md.ingress_tstamp > 0) {
                val = ig_md.ingress_tstamp;
            } else {
                val = 1;
            }
            ret = 1;
        } };

    RegisterAction<bit<32>, bit<16>, bit<1>>(p2p_dsts_stage2_reg) p2p_dsts_stage2_update_or_reset = {
        void apply(inout bit<32> val, out bit<1> present) {
            // Determine if current value is stale; also works if value == 0
            if ((val > 0) && (ig_md.ingress_tstamp - val > TIME_DUR_CUTOFF)) {
                val = 0; present = 0;
            } else if (val > 0) {
                val = ig_md.ingress_tstamp; present = 1;
            } } };


    action set_all_pkts_count_to_ethernet_src() {
        hdr.ethernet.src_addr_id  = ig_md.all_pkts_count[23:0];
        hdr.ethernet.src_addr_oui = 16w0x0 ++ ig_md.all_pkts_count[31:24];
    }
    
    action set_zoom_pkts_count_to_ethernet_dst() {
        hdr.ethernet.dst_addr_id  = ig_md.zoom_pkts_count[23:0];
        hdr.ethernet.dst_addr_oui = 16w0x0 ++ ig_md.zoom_pkts_count[31:24];
    }


    apply {

        // Deployment version: Extract MSB 32 bits of the ingress MAC timestamp
        ig_md.ingress_tstamp = ig_intr_md.ingress_mac_tstamp[47:16];

        // // Testing version (comment out for deployment): Extract LSB 32 bits of the ingress MAC timestamp
        // ig_md.ingress_tstamp = ig_intr_md.ingress_mac_tstamp[31:0];

        ig_md.all_pkts_count = all_pkts_incr_and_read.execute(0);

        // Check if source or dest IP in Zoom server list
        if (hdr.ipv4.isValid()) {
            match_zoom_srv.apply();
        }

        if (hdr.tcp.isValid() && (ig_md.zoom_srv_src_matched == 1 || ig_md.zoom_srv_dst_matched == 1)) {
            // Source/dest in Zoom server list and TCP packet: accept as Zoom
            
            ig_md.is_zoom_pkt = 1;
        
        } else if (hdr.udp.isValid() && (ig_md.zoom_srv_src_matched == 1 || ig_md.zoom_srv_dst_matched == 1)) {
            // Source/dest in Zoom server list and UDP packet: accept as Zoom and also check for STUN

            match_stun.apply();

            if (ig_md.stun_src_port_matched == 1 || ig_md.stun_dst_port_matched == 1) {
                // If STUN packet, write to P2P registers

                bit<16> stage0_idx = ig_md.stun_peer_addr[31:16];
                bit<16> stage1_idx = ig_md.stun_peer_addr[15:0];
                bit<16> stage2_idx = ig_md.stun_peer_port;

                p2p_srcs_stage0_set.execute(stage0_idx);
                p2p_srcs_stage1_set.execute(stage1_idx);
                p2p_srcs_stage2_set.execute(stage2_idx);

                p2p_dsts_stage0_set.execute(stage0_idx);
                p2p_dsts_stage1_set.execute(stage1_idx);
                p2p_dsts_stage2_set.execute(stage2_idx);

            }

            ig_md.is_zoom_pkt = 1;
                
        } else if (hdr.udp.isValid()) {
            // Source/dest NOT in Zoom server list and UDP packet: check if Zoom P2P

            match_campus_src.apply();
            match_campus_dst.apply();

            if (hdr.udp.src_port > 1023 && hdr.udp.dst_port > 1023) {
                ig_md.non_srv_port_matched = 1;
            }

            bit<1> p2p_src_matched = 0;
            bit<1> p2p_dst_matched = 0;

            bit<1> p2p_src_stage0_matched = 0;
            bit<1> p2p_src_stage1_matched = 0;
            bit<1> p2p_src_stage2_matched = 0;

            bit<1> p2p_dst_stage0_matched = 0;
            bit<1> p2p_dst_stage1_matched = 0;
            bit<1> p2p_dst_stage2_matched = 0;

            if (ig_md.non_srv_port_matched == 1 && ig_md.campus_src_matched == 1) {
                
                bit<16> src_stage0_idx = hdr.ipv4.src_addr[31:16];
                bit<16> src_stage1_idx = hdr.ipv4.src_addr[15:0];
                bit<16> src_stage2_idx = hdr.udp.src_port;

                p2p_src_stage0_matched = p2p_srcs_stage0_update_or_reset.execute(src_stage0_idx);
                p2p_src_stage1_matched = p2p_srcs_stage1_update_or_reset.execute(src_stage1_idx);
                p2p_src_stage2_matched = p2p_srcs_stage2_update_or_reset.execute(src_stage2_idx);
            
            }
                
            if (ig_md.non_srv_port_matched == 1 && ig_md.campus_dst_matched == 1) {

                bit<16> dst_stage0_idx = hdr.ipv4.dst_addr[31:16];
                bit<16> dst_stage1_idx = hdr.ipv4.dst_addr[15:0];
                bit<16> dst_stage2_idx = hdr.udp.dst_port;

                p2p_dst_stage0_matched = p2p_dsts_stage0_update_or_reset.execute(dst_stage0_idx);
                p2p_dst_stage1_matched = p2p_dsts_stage1_update_or_reset.execute(dst_stage1_idx);
                p2p_dst_stage2_matched = p2p_dsts_stage2_update_or_reset.execute(dst_stage2_idx);
            
            }

            if (p2p_src_stage0_matched == 1 && p2p_src_stage1_matched == 1 && p2p_src_stage2_matched == 1) {
                p2p_src_matched = 1;
            }

            if (p2p_dst_stage0_matched == 1 && p2p_dst_stage1_matched == 1 && p2p_dst_stage2_matched == 1) {
                p2p_dst_matched = 1;
            }

            if (p2p_src_matched == 1 || p2p_dst_matched == 1) {
                ig_md.is_zoom_pkt = 1;
            }
        }

        if (ig_md.is_zoom_pkt == 1) {

            ig_md.zoom_pkts_count = zoom_pkts_incr_and_read.execute(0);

            set_all_pkts_count_to_ethernet_src();
            set_zoom_pkts_count_to_ethernet_dst();

            set_egress_port(DEFAULT_EGRESS_PORT);

        }
        
        ig_tm_md.bypass_egress = 1;
        
    }
}

// Ingress deparsing

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

// Empty blocks for egress:

parser SwitchEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
    state start {
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {

    apply { }
}

control SwitchEgress(
        inout empty_header_t hdr,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    
    apply { }
}

// Switch pipeline

Pipeline(SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        SwitchEgressParser(),
        SwitchEgress(),
        SwitchEgressDeparser()) pipe;

Switch(pipe) main;
