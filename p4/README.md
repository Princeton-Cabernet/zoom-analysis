
## P4 Zoom Capture

### Read before executing the P4 program:

1. The P4 program is located in `src/zoom_capture.p4`.

2. For P2P Zoom connections, when a `STUN` packet is seen, a record (4-tuple) corresponding to the local Zoom client is stored in memory. The corresponding timestamp is also stored, and is updated every time a new packet from the connection is seen. If no new packet is seen in a while (defined by the `TIME_DUR_CUTOFF` constant in the program), the record is purged from memory.

3. The `match_zoom_srv` match-action table matches on publicly known [Zoom IP prefixes](https://support.zoom.us/hc/en-us/articles/201362683-Zoom-network-firewall-or-proxy-server-settings). The corresponding table entries are defined in a separate file located in `src/entries_match_zoom_server.p4inc`, which is then included in the program. Since Zoom can change its prefixes over time, please check and update the entries in this file if needed.

4. The `match_campus_src` and `match_campus_dst` match-action tables match on campus IP prefixes. The corresponding table entries are defined in separate files in the locations `src/entries_match_campus_sources.p4inc` and `src/entries_match_campus_destinations.p4inc` respectively. These entries currently correspond to the [Princeton campus network](https://www.net.princeton.edu/ip-network-ranges.html); please change these to match your network.

5. The program sets the ethernet source address of the outgoing packet to the total packet count (32-bit integer) seen so far. Likewise, it sets the ethernet destination address to the Zoom packet count (32-bit integer) seen so far. To disable this feature and to preserve the original ethernet addresses, comment out the calls to `set_all_pkts_count_to_ethernet_src()` and `set_zoom_pkts_count_to_ethernet_dst()`.

6. We used the ONTAS system ([paper](https://p4campus.cs.princeton.edu/pubs/ontas_netai_paper.pdf), [code](https://github.com/Princeton-Cabernet/p4-projects/tree/master/ONTAS/tofino_p4_14)) to anonymize personally identifiable information (e.g., IP addresses of campus clients) in the outgoing packets. We adapted the ONTAS code for P4<sub>16</sub> and placed it directly in the egress pipeline of our P4 program.

### Test the program:

1. Run `sudo python3 test/send.py [-i INTERFACE] -t TYPE` to send packets to the Zoom capture program. Specify (optionally) the interface on which to send packets; the default is `veth1`. The `-t/--type` parameter is required, and can be set to `server`, `stun`, `p2p`, or `other` depending on the desired type of packets.

2. Run `sudo test/receive.py -i INTERFACE` to receive packets output by the Zoom capture program. Specify the interface on which to listen using the `-i/--interface` parameter.

3. **Expected results:** The `server` packets should be allowed (by the program), the `stun` packet should be allowed, and the `others` packets should be dropped. If the `stun` packet is already seen, the first `p2p` packet should be allowed and the second one should be dropped. If the `stun` packet is not seen, both `p2p` packets should be dropped.
