#include "zoom.h"

char zoom::media_type_to_char(zoom::media_type t) {

    switch (t) {
        case media_type::audio:  return 'a';
        case media_type::video:  return 'v';
        case media_type::screen: return 's';
    }

    return '0';
}

char zoom::stream_type_to_char(zoom::stream_type t) {

    switch (t) {
        case stream_type::media: return 'm';
        case stream_type::fec:   return 'f';
    }

    return '0';
}

zoom::media_stream_key zoom::media_stream_key::from_pkt(const pkt& pkt) {

    enum media_type media_type;

    if (pkt.zoom_media_type == zoom::AUDIO_TYPE) {
        media_type = media_type::audio;
    } else if (pkt.zoom_media_type == zoom::VIDEO_TYPE) {
        media_type = media_type::video;
    } else if (pkt.zoom_media_type == zoom::P2P_SCREEN_SHARE_TYPE
        || pkt.zoom_media_type == zoom::SRV_SCREEN_SHARE_TYPE) {

        media_type = media_type::screen;
    }

    return {
        .ip_5t       = pkt.ip_5t,
        .rtp_ssrc    = pkt.proto.rtp.ssrc,
        .media_type  = media_type,
        .stream_type = pkt.proto.rtp.pt == 110 ? stream_type::fec : stream_type::media
    };
}

bool zoom::media_stream_key::operator<(const struct media_stream_key& a) const {

    return std::tie(ip_5t, rtp_ssrc, media_type, stream_type)
        < std::tie(a.ip_5t, a.rtp_ssrc, a.media_type, a.stream_type);
}

bool zoom::media_stream_key::operator==(const struct media_stream_key& a) const {

    return std::tie(ip_5t, rtp_ssrc, media_type, stream_type)
        == std::tie(a.ip_5t, a.rtp_ssrc, a.media_type, a.stream_type);
}

/*
zoom::rtp_stream_key zoom::rtp_stream_key::from_pkt(const zoom::pkt& pkt) {

    return {
        .ip_5t    = pkt.ip_5t,
        .rtp_ssrc = pkt.proto.rtp.ssrc,
        .rtp_pt   = pkt.proto.rtp.pt,
    };
}

bool zoom::rtp_stream_key::operator<(const struct rtp_stream_key& a) const {

    return std::tie(ip_5t, rtp_ssrc, rtp_pt)
           < std::tie(a.ip_5t, a.rtp_ssrc, a.rtp_pt);
}

bool zoom::rtp_stream_key::operator==(const struct rtp_stream_key& a) const {

    return std::tie(ip_5t, rtp_ssrc, rtp_pt)
           == std::tie(a.ip_5t, a.rtp_ssrc, a.rtp_pt);
}
*/

zoom::pkt::pkt()
    : zoom_srv_type(0),
      zoom_media_type(0),
      pkts_in_frame(0),
      udp_pl_len(0),
      pcap_frame_len{0} {

    flags.p2p      = 0;
    flags.srv      = 0;
    flags.rtp      = 0;
    flags.rtcp     = 0;
    flags.to_srv   = 0;
    flags.from_srv = 0;
}

zoom::pkt::pkt(const struct zoom::headers& hdr, timeval tv, std::size_t pcap_frame_len, bool is_p2p) {

    ts.s = tv.tv_sec;
    ts.us = tv.tv_usec;

    flags.p2p = is_p2p ? 1 : 0;
    flags.srv = is_p2p ? 0 : 1;

    ip_5t.ip_src = ntohl(hdr.ip->src_addr);
    ip_5t.ip_dst = ntohl(hdr.ip->dst_addr);
    ip_5t.ip_proto = hdr.ip->next_proto_id;

    this->pcap_frame_len = pcap_frame_len;

    if (ip_5t.ip_proto == 17) {
        ip_5t.tp_src = ntohs(hdr.udp->src_port);
        ip_5t.tp_dst = ntohs(hdr.udp->dst_port);
        udp_pl_len = ntohs(hdr.udp->dgram_len);
    }

    if (!is_p2p) {
        zoom_srv_type = hdr.zoom_outer[0];
        flags.to_srv = (hdr.zoom_outer[7] == 0x00);
        flags.from_srv = (hdr.zoom_outer[7] == 0x04);
    }

    zoom_media_type = hdr.zoom_inner[0];

    if (zoom_media_type == 0x10) {
        pkts_in_frame = hdr.zoom_inner[23];
    }

    if (hdr.rtp) {
        flags.rtp = 1;

        proto.rtp.ssrc = ntohl(hdr.rtp->ssrc);
        proto.rtp.ts = ntohl(hdr.rtp->ts);
        proto.rtp.seq = ntohs(hdr.rtp->seq);
        proto.rtp.pt = hdr.rtp->payload_type();
    }

    if (hdr.rtcp) {
        flags.rtcp = 1;

        proto.rtcp.ssrc = ntohl(hdr.rtcp->ssrc);
        proto.rtcp.pt = hdr.rtcp->pt;

        if (proto.rtcp.pt == 200) { // sender report
            proto.rtcp.rtp_ts = ntohl(hdr.rtcp->msg.sr.rtp_ts);
            proto.rtcp.ntp_ts_msw = ntohl(hdr.rtcp->msg.sr.ntp_ts_msw);
            proto.rtcp.ntp_ts_lsw= ntohl(hdr.rtcp->msg.sr.ntp_ts_lsw);
        }
    }

    std::memcpy(rtp_ext1, hdr.rtp_ext1, 3);
}
/*
zoom::media_stream_meta zoom::media_stream_meta::from_pkt(const zoom::pkt& pkt) {

    enum media_type media_type;

    if (pkt.zoom_media_type == zoom::AUDIO_TYPE) {
        media_type = media_type::audio;
    } else if (pkt.zoom_media_type == zoom::VIDEO_TYPE) {
        media_type = media_type::video;
    } else if (pkt.zoom_media_type == zoom::P2P_SCREEN_SHARE_TYPE
               || pkt.zoom_media_type == zoom::SRV_SCREEN_SHARE_TYPE) {

        media_type = media_type::screen;
    }

    return {
        .ip_5t       = pkt.ip_5t,
        .rtp_ssrc    = pkt.proto.rtp.ssrc,
        .media_type  = media_type,
        .stream_type = pkt.proto.rtp.pt == 110 ? stream_type::fec : stream_type::media
    };
}
*/
struct zoom::headers zoom::parse_zoom_pkt_buf(const unsigned char* buf, bool includes_eth, bool is_p2p) {

    struct headers hdr;
    unsigned eth_offset = includes_eth ? net::eth::HDR_LEN : 0;

    hdr.ip = (net::ipv4::hdr*) (buf + eth_offset);

    if (hdr.ip->next_proto_id == 17) {

        hdr.udp = (net::udp::hdr*) (buf + eth_offset + hdr.ip->ihl_bytes());
        hdr.udp_pl_offset = eth_offset + hdr.ip->ihl_bytes() + net::udp::HDR_LEN;
        auto* udp_pl = buf + hdr.udp_pl_offset;

        if (is_p2p) {
            hdr.zoom_inner = udp_pl;
        } else {
            hdr.zoom_outer = udp_pl;

            if (hdr.zoom_outer[0] == SRV_MEDIA_TYPE) {
                hdr.zoom_inner = udp_pl + 8;
            }
        }

        if (!is_p2p && udp_pl[0] == SRV_MEDIA_TYPE) {
            hdr.zoom_outer = udp_pl;
            hdr.zoom_inner = udp_pl + 8;
        } else {
            hdr.zoom_inner = udp_pl;
        }

        if (hdr.zoom_inner && (hdr.zoom_inner[0] == AUDIO_TYPE
            || hdr.zoom_inner[0] == VIDEO_TYPE
            || (is_p2p && hdr.zoom_inner[0] == P2P_SCREEN_SHARE_TYPE))
            || (!is_p2p && hdr.zoom_inner[0] == SRV_SCREEN_SHARE_TYPE
                && hdr.zoom_inner[7] == P2P_SCREEN_SHARE_TYPE)
            || (hdr.zoom_inner[0] == RTCP_SR_TYPE
                || hdr.zoom_inner[0] == RTCP_SR_SD_TYPE)) {

            if (hdr.zoom_inner[0] == AUDIO_TYPE) {
                hdr.rtp_rtcp_offset = hdr.udp_pl_offset + (is_p2p ? 0 : 8) + 19;
                hdr.rtp = (rtp::hdr*) (buf + hdr.rtp_rtcp_offset);
            } else if (hdr.zoom_inner[0] == VIDEO_TYPE) {

                if (hdr.zoom_inner[20] == 0x02) {
                    hdr.rtp_rtcp_offset = hdr.udp_pl_offset + (is_p2p ? 0 : 8) + 24;
                    hdr.rtp = (rtp::hdr*) (buf + hdr.rtp_rtcp_offset);
                } else {
                    hdr.rtp_rtcp_offset = hdr.udp_pl_offset + (is_p2p ? 0 : 8) + 20;
                    hdr.rtp = (rtp::hdr*) (buf + hdr.rtp_rtcp_offset);
                }

            } else if (is_p2p && hdr.zoom_inner[0] == P2P_SCREEN_SHARE_TYPE) {
                hdr.rtp_rtcp_offset = hdr.udp_pl_offset + 20;
                hdr.rtp = (rtp::hdr*) (buf + hdr.rtp_rtcp_offset);
            } else if (!is_p2p && hdr.zoom_inner[0] == SRV_SCREEN_SHARE_TYPE
                && hdr.zoom_inner[7] == P2P_SCREEN_SHARE_TYPE) {
                hdr.rtp_rtcp_offset = hdr.udp_pl_offset + 35;
                hdr.rtp = (rtp::hdr*) (buf + hdr.rtp_rtcp_offset);
            } else if (hdr.zoom_inner[0] == RTCP_SR_TYPE || hdr.zoom_inner[0] == RTCP_SR_SD_TYPE) {
                hdr.rtp_rtcp_offset = hdr.udp_pl_offset + (is_p2p ? 0 : 8) + 16;
                hdr.rtcp = (rtcp::hdr*) (buf + hdr.rtp_rtcp_offset);
            }

            if (hdr.rtp && hdr.rtp->extension()) { // get rtp extension header with type == 1

                auto* rtp_ext_ptr = buf + hdr.rtp_rtcp_offset + rtp::HDR_LEN;
                auto ext_bytes =  (rtp_ext_ptr[2] << 8) + (rtp_ext_ptr[3]) * 4;

                for (auto ext_byte_i = 4; ext_byte_i < 4 + ext_bytes;) {
                    if (rtp_ext_ptr[ext_byte_i] != 0) { // 0 -> padding byte

                        auto type = (rtp_ext_ptr[ext_byte_i] >> 4) & 0x0f;
                        auto len = (rtp_ext_ptr[ext_byte_i] & 0x0f) + 1;

                        if (type == 1 && len == 3) {
                            std::memcpy(hdr.rtp_ext1, rtp_ext_ptr + ext_byte_i + 1, 3);
                            break;
                        }

                        ext_byte_i += (len + 1);
                    } else {
                        ext_byte_i++;
                    }
                }
            }
        }
    }

    return hdr;
}
