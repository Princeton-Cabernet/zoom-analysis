
zoom_o = Proto("zoom_o", "Zoom SFU Encapsulation")
zoom_o.fields.type = ProtoField.new("Type", "zoom_o.type", ftypes.UINT8)
zoom_o.fields.seq = ProtoField.new("Sequence number", "zoom_o.seq", ftypes.UINT16)
zoom_o.fields.dir = ProtoField.new("Direction", "zoom_o.dir", ftypes.UINT8)

zoom = Proto("zoom", "Zoom Media Encapsulation")
zoom.fields.type = ProtoField.new("Type", "zoom.type", ftypes.UINT8)
zoom.fields.seq = ProtoField.new("Sequence number", "zoom.seq", ftypes.UINT16)
zoom.fields.ts = ProtoField.new("Timestamp", "zoom.ts", ftypes.UINT32)
zoom.fields.frame_num = ProtoField.new("Frame number", "zoom.frame_num", ftypes.UINT16)
zoom.fields.frame_pkt_count = ProtoField.new("Packets in frame", "zoom.frame_pkt_count", ftypes.UINT8)

zoom.fields.t13ts = ProtoField.new("T13 Timestamp", "zoom.t13ts", ftypes.UINT16)
zoom.fields.t13s = ProtoField.new("T13 Sequence number", "zoom.t13s", ftypes.UINT16)
zoom.fields.t13t = ProtoField.new("T13 Subtype", "zoom.t13t", ftypes.UINT8)
zoom.fields.t32ts = ProtoField.new("T32 Timestamp", "zoom.t32ts", ftypes.UINT32)

function get_type_desc(type)
    local desc = "Unknown"

    if type == 13 then
        desc = "Screen Share"
    elseif type == 15 then
        desc = "Audio"
    elseif type == 16 then
        desc = "Video"
    elseif type == 30 then
        desc = "Screen Share"
    elseif type == 33 or type == 34 or type == 35 then
        desc = "RTCP"
    end

    return desc
end

function get_zoom_o_dir_desc(dir)
    local desc = "Unknown"

    if dir == 0 then
        desc = "to Zoom"
    elseif dir == 4 then
        desc = "from Zoom"
    end

    return desc
end

-- Zoom media encapsulation (inner header):
function zoom.dissector(buf, pkt, tree)
    len = buf:len()
    if len == 0 then return end
    pkt.cols.protocol = zoom.name

    local inner_type = buf(0, 1):uint()

    local t = tree:add(zoom, buf(), "Zoom Media Encapsulation")
    t:add(zoom.fields.type, buf(0, 1)):append_text(" (" .. get_type_desc(inner_type) .. ")")

    if inner_type == 1 then
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        Dissector.get("rtp"):call(buf(26):tvb(), pkt, tree)
    elseif inner_type == 13 then
        t:add(zoom.fields.t13ts, buf(1, 2))
        t:add(zoom.fields.t13s, buf(3, 2))
        t:add(zoom.fields.t13t, buf(7, 1))

        if buf(7, 1):uint() == 0x1e then -- server screen sharing
            t:add(zoom.fields.seq, buf(16, 2))
            t:add(zoom.fields.ts, buf(18, 4))
            Dissector.get("rtp"):call(buf(27):tvb(), pkt, tree)
        end

    elseif inner_type == 15 then
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        Dissector.get("rtp"):call(buf(19):tvb(), pkt, tree)
    elseif inner_type == 16 then
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))

        if (buf(20, 1):uint() == 0x02) then
            t:add(zoom.fields.frame_num, buf(21, 2))
            t:add(zoom.fields.frame_pkt_count, buf(23, 1))
            Dissector.get("rtp"):call(buf(24):tvb(), pkt, tree)
        else
            Dissector.get("rtp"):call(buf(20):tvb(), pkt, tree)
        end

    elseif inner_type == 21 then -- unclear what this type is
        t:add(zoom.fields.seq, buf(13, 2))
    elseif inner_type == 30 then -- P2P screen sharing
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        Dissector.get("rtp"):call(buf(20):tvb(), pkt, tree)
    elseif inner_type == 32 then -- unclear what this type is
        t:add(zoom.fields.t32ts, buf(19, 4))
    elseif inner_type == 33 or inner_type == 34 or inner_type == 35 then
        Dissector.get("rtcp"):call(buf(16):tvb(), pkt, tree)
    else
        Dissector.get("data"):call(buf(15):tvb(), pkt, tree)
    end
end

-- Zoom server encapsulation (outer header):
function zoom_o.dissector(buf, pkt, tree)
    length = buf:len()
    if length == 0 then return end
    pkt.cols.protocol = zoom_o.name

    local t = tree:add(zoom_o, buf(), "Zoom SFU Encapsulation")
    t:add(zoom_o.fields.type, buf(0, 1))
    t:add(zoom_o.fields.seq, buf(1, 2))
    t:add(zoom_o.fields.dir, buf(7, 1)):append_text(" (" .. get_zoom_o_dir_desc(buf(7, 1):uint()) .. ")")

    local outer_type = buf(0, 1):uint()

    if outer_type == 5 then
        Dissector.get("zoom"):call(buf(8):tvb(), pkt, tree)
    else
        Dissector.get("data"):call(buf(8):tvb(), pkt, tree)
    end
end

-- per-default dissect all UDP port 8801 as Zoom Server Encap.
DissectorTable.get("udp.port"):add(8801, zoom_o)

-- allow selecting Zoom from "Decode as ..." context menu (for P2P traffic):
DissectorTable.get("udp.port"):add_for_decode_as(zoom)
