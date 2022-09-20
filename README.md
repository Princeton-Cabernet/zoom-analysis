## Zoom Analysis

[![build-test](https://github.com/Princeton-Cabernet/zoom-analysis/actions/workflows/build-test.yml/badge.svg)](https://github.com/Princeton-Cabernet/zoom-analysis/actions/workflows/build-test.yml)

### Build Project

    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make

### Run Unit Tests

    (cd build && make test)

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
