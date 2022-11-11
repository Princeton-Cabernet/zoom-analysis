
## P4 Zoom Capture

### Build and run the program:

1. Setup virtual interfaces: `sudo $SDE_INSTALL/bin/veth_setup.sh`
2. Build P4 program and install for simulator: `make`
3. Run simulator: `make run-sim`
4. Run *bf_switchd*: `make run-bfswitchd`
5. Set egress port, e.g.: `control/set_egress_port_and_ontas.py 1 -i "['140.180.0.0/16','128.112.1.0/24']"`
6. Run test: `sudo test/send.py` and `sudo test/receive.py`

### Read registers and counters from control plane:

* Use `bfrt_python` at top level of *bfshell* (from *make run-bfswitchd*)

#### Packet Counter:

**all packets:**

    bfrt.zoom_capture.pipe.SwitchIngress.all_pkts_counter.operation_counter_sync()
    bfrt.zoom_capture.pipe.SwitchIngress.all_pkts_counter.dump()

**zoom packets:**

    bfrt.zoom_capture.pipe.SwitchIngress.zoom_pkts_counter.operation_counter_sync()
    bfrt.zoom_capture.pipe.SwitchIngress.zoom_pkts_counter.dump()

#### Registers:

**p2p sources:**

    bfrt.zoom_capture.pipe.SwitchIngress.p2p_srcs.operation_register_sync()
    bfrt.zoom_capture.pipe.SwitchIngress.p2p_srcs.dump()

**p2p destinations:**

    bfrt.zoom_capture.pipe.SwitchIngress.p2p_dsts.operation_register_sync()
    bfrt.zoom_capture.pipe.SwitchIngress.p2p_dsts.dump()
