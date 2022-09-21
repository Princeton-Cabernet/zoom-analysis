## Analyzing Zoom Meeting Characteristics and Performance from Packet Captures

[![build-test](https://github.com/Princeton-Cabernet/zoom-analysis/actions/workflows/build-test.yml/badge.svg)](https://github.com/Princeton-Cabernet/zoom-analysis/actions/workflows/build-test.yml)

This repository contains tools to analyze various performance-related metrics of Zoom meetings
solely from packet traces of Zoom traffic. The tools allow inferring the types of media (audio,
video, screen share) used, media bit rates, video frame rates and frame sizes, user participation
(muted, speaking, silent), and network-related metrics such as frame-level jitter and overall latency
from *.pcap* data captured using, for example, Wireshark. We also provide a Wireshark plugin to
analyze Zoom traffic interactively using the Wireshark UI.

The techniques used to extract these metrics and make inferences based on them are described in our paper:
> Oliver Michel, Satadal Sengupta, Hyojoon Kim, Ravi Netravali, and Jennifer Rexford. 2022. Enabling Passive Measurement of Zoom Performance in Production Networks. In Proceedings of the 22nd ACM Internet Measurement Conference (IMC ’22), October 25–27, 2022, Nice, France. ACM, New York, NY, USA, 17 pages. https://doi.org/10.1145/3517745.3561414

### Build Project

* Prerequisites: gcc, cmake, pkg-config, wget, and libpcap
    * Under Ubuntu, run `apt-get install cmake g++ libpcap-dev pkg-config wget`

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

### Run Unit Tests

```
(cd build && make test)
```
### Applications

#### zoom_flows

Extracts packets associated with Zoom and prints per-flow statistics.
* reads all files in directory in lexicographical order of file names if *-i* is a directory path
* writes flow-level statistics to CSV if *-f* specified
* writes Zoom type statistics to CSV if *-t* specified
* writes Zoom-related packets to PCAP if *-p* specified
* generates time series of packet and byte rate in 1s buckets if *-r* specified
* writes records for Zoom packets to custom binary format if *-z* specified
* only considers/filters P2P and STUN packets if *-2* specified (flow summary will still include all flows)

```
usage: zoom_flows [OPTION...]
  -i, --in IN.pcap or IN/  input file/path
  -f, --flows-out OUT.csv  flow summary output file (optional)
  -t, --types-out OUT.csv  type summary output file (optional)
  -p, --pcap-out OUT.pcap  filtered pcap output file (optional)
  -r, --rate-out OUT.csv   rate time series output file (optional)
  -z, --zpkt-out OUT.zpkt  zoom packets binary output file (optional)
  -2, --p2p-only           only process STUN and P2P packets (optional)
  -h, --help               print this help message
```

#### zoom_rtp

Collects statistics about RTP streams in Zoom traffic.
* reads the *.zpkt* input file at the path specified by *-i*
* writes RTP-stream-level statistics to CSV if *-s* specified
* writes a detailed packet log to CSV if *-p* specified
* writes frames to CSV if *-f* specified
* writes performance-related statistics in 1s intervals to CSV if *-t* specified

```
usage: zoom_rtp [OPTION...]
  -i, --in IN.zpkt           input file
  -s, --streams-out OUT.csv  output path for stream summary (optional)
  -p, --pkts-out OUT.csv     output path for packet log (optional)
  -f, --frames-out OUT.csv   output path for frame log (optional)
  -t, --stats-out OUT.csv    output path for 1s statistics (optional)
  -h, --help                 print this help message
```

#### zoom_meetings

Groups packets by media streams and meetings.
* reads the *.zpkt* input file at the path specified by *-i*
* writes the set of unique (non-duplicate) media streams to CSV if *-u* specified
* writes meetings to CSV if *-m* specified

```
usage: zoom_meetings [OPTION...]
  -i, --in IN.zpkt                 input file name
  -u, --unique-out STREAMS.csv     unique streams out file name (optional)
  -m, --meetings-out MEETINGS.csv  meetings out file name (optional)
  -h, --help                       print this help message
```

### License

This project's source code is released under the [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html). In particular,
* You are entitled to redistribute the program or its modified version, however you must also make available the full source code and a copy of the license to the recipient. Any modified version or derivative work must also be licensed under the same licensing terms.
* You also must make available a copy of the modified program's source code available, under the same licensing terms, to all users interacting with the modified program remotely through a computer network.
