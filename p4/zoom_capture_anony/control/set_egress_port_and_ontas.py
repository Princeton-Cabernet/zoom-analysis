#!/usr/bin/env python

import argparse
import os
import sys
import logging
import binascii
import socket
import struct

def print_table(table, target):
    
    print("table {}:".format(table.info.name))

    entries = table.entry_get(target)

    for i, (data, key) in enumerate(entries):
        print("  - entry {}: {} -> {}".format(i, key, data))


def add_table_entry(table, target, keys, action, data):

    key_list = [table.make_key(keys)]
    data_list = [table.make_data(data, action_name = action)]

    table.entry_add(target, key_list, data_list,
        bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)


def flush_table(table, target):
    
    keys = []
    entries = table.entry_get(target)
    
    for _, key in entries:
        keys.append(key)
    
    if len(keys) > 0:
        table.entry_del(target, keys)

def do_bf_imports(sde_path):

    bf_python_paths = [
        "{0}/install/lib/python2.7/site-packages/p4testutils",
        "{0}/install/lib/python2.7/site-packages/tofino",
        "{0}/install/lib/python2.7/site-packages"
    ]

    for path in bf_python_paths:
        sys.path.append(path.format(sde_path))

    import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
    import bfrt_grpc.client as gc 

    global bfruntime_pb2
    global gc

def main():
    ###################
    # EXAMPLE COMMAND: 
    #   python set_egress_port_and_ontas.py -p zoom_capture_anony 4 -i "['140.180.0.0/16','128.112.0.0/24']"
    ###################

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--p4", type = str, required = False,
        default = "src/zoom_capture_anony.p4",
        help = "P4 main program path [default: src/zoom_capture_anony.p4]")
    parser.add_argument("-s", "--sde", type = str, required = False,
        default = os.environ["SDE"],
        help = "BF SDE path [default: SDE environment variable]")
    parser.add_argument("-g", "--grpc", type = str, required = False,
        default = "localhost:50052",
        help = "gRPC address [default: localhost:50052]")
    parser.add_argument("egress_port", type = int, nargs = 1,
        help = "egress port for matched packets")
    parser.add_argument("-i", "--ip", type = str, required = True,
        dest="prefixes",
        help = "IP prefixes in list format (e.g., ['1.2.3.4/16', '2.3.4.5/24']")
    
    args = parser.parse_args()
    p4_name = os.path.splitext(os.path.basename(args.p4))[0]

    print("p4_path: {}".format(args.p4))
    print("p4_name: {}".format(p4_name))
    print("sde: {}".format(args.sde))
    print("grpc: {}".format(args.grpc))
    print("egress_port: {}".format(args.egress_port[0]))
    print("anony ip prefixes: {}".format(args.prefixes))

    do_bf_imports(args.sde)

    gc.logger.setLevel(logging.CRITICAL)

    client_id = 1
    device_id = 0

    interface = gc.ClientInterface(args.grpc, client_id = client_id,
        device_id = device_id)

    interface.bind_pipeline_config(p4_name)
    target = gc.Target(device_id = device_id, pipe_id = 0xffff)
    bfrt_info = interface.bfrt_info_get(p4_name)

    send_pkt_table = bfrt_info.table_get("send_pkt")
    
    flush_table(send_pkt_table, target)

    add_table_entry(send_pkt_table, target,
        [gc.KeyTuple("ig_md.is_zoom_pkt", 1)],
        "set_egress_port", [gc.DataTuple("port", args.egress_port[0])])
    
    print_table(send_pkt_table, target)

    # Add ONTAS rules at egress
    try: 
        # Basic tables
        anony_mac_src_id_table = bfrt_info.table_get("anony_mac_src_id_tb")
        if anony_mac_src_id_table is not None:
            flush_table(anony_mac_src_id_table, target)
            add_table_entry(anony_mac_src_id_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)],
                "hash_mac_src_id_action",[])
            print_table(anony_mac_src_id_table, target)

        anony_mac_dst_id_table = bfrt_info.table_get("anony_mac_dst_id_tb")
        if anony_mac_dst_id_table is not None:
            flush_table(anony_mac_dst_id_table, target)
            add_table_entry(anony_mac_dst_id_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)],
                "hash_mac_dst_id_action",[])
            print_table(anony_mac_dst_id_table, target)

        anony_arp_mac_src_id_table = bfrt_info.table_get("anony_arp_mac_src_id_tb")
        if anony_arp_mac_src_id_table is not None:
            flush_table(anony_arp_mac_src_id_table, target)
            add_table_entry(anony_arp_mac_src_id_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)], 
                "hash_arp_mac_src_id_action",[])
            print_table(anony_arp_mac_src_id_table, target)
 
        anony_arp_mac_dst_id_table = bfrt_info.table_get("anony_arp_mac_dst_id_tb")
        if anony_arp_mac_dst_id_table is not None:
            flush_table(anony_arp_mac_dst_id_table, target)
            add_table_entry(anony_arp_mac_dst_id_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)], 
                "hash_arp_mac_dst_id_action",[])
            print_table(anony_arp_mac_dst_id_table, target)
 
        multicast_mac_catch_table = bfrt_info.table_get("multicast_mac_catch_tb")
        if multicast_mac_catch_table is not None:
            flush_table(multicast_mac_catch_table, target)
            add_table_entry(multicast_mac_catch_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)], 
                "multicast_mac_catch_action",[])
            print_table(multicast_mac_catch_table, target)

        ipv4_ip_overwite_table = bfrt_info.table_get("ipv4_ip_overwite_tb")
        if ipv4_ip_overwite_table is not None:
            flush_table(ipv4_ip_overwite_table, target)
            add_table_entry(ipv4_ip_overwite_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)],
                "ip_overwrite_action",[])
            print_table(ipv4_ip_overwite_table, target)

        arp_ip_overwrite_table = bfrt_info.table_get("arp_ip_overwrite_tb")
        if arp_ip_overwrite_table is not None:
            flush_table(arp_ip_overwrite_table, target)
            add_table_entry(arp_ip_overwrite_table, target,
                [gc.KeyTuple("hdr.zoom.is_zoom_pkt", 1)],
                "arp_ip_overwrite_action",[])
            print_table(arp_ip_overwrite_table, target)
  
    except:
        print("\nERROR: Either cannot find ONTAS tables or failed to add entries to them.\n")

    # IP prefixes to hash
    anony_srcip_table = bfrt_info.table_get("anony_srcip_tb")
    anony_dstip_table = bfrt_info.table_get("anony_dstip_tb")
    flush_table(anony_srcip_table, target)
    flush_table(anony_dstip_table, target)

    prefix_list = eval(args.prefixes)
    iphex = 0
    mask1 = 0
    mask2 = 0

    for p in prefix_list:
        ip_and_mask = p.split("/")
        iphex = struct.unpack("!L", socket.inet_aton(ip_and_mask[0]))[0]
        if ip_and_mask[1] == "8":
            mask1 = 0xff000000
            mask2 = 0x000000ff
        elif ip_and_mask[1] == "16":
            mask1 = 0xffff0000
            mask2 = 0x0000ffff
        elif ip_and_mask[1] == "24": 
            mask1 = 0xffffff00
            mask2 = 0x000000ff
        elif ip_and_mask[1] == "32": 
            mask1 = 0xffffffff
            mask2 = 0x00000000
        else:
            print("Wrong IP prefix input. Can only handle /8, /16, /24, and /32.")

        if anony_srcip_table is not None and mask1!='' and mask2!='':
            add_table_entry(anony_srcip_table, target, [gc.KeyTuple("hdr.ipv4.src_addr", iphex, mask=mask1)], 
                            "prepare_srcip_hash_action",[gc.DataTuple("mask1",mask1),gc.DataTuple("mask2",mask2)])

        if anony_dstip_table is not None and mask1!='' and mask2!='':
            add_table_entry(anony_dstip_table, target, [gc.KeyTuple("hdr.ipv4.dst_addr", iphex, mask=mask1)], 
                            "prepare_dstip_hash_action",[gc.DataTuple("mask1",mask1),gc.DataTuple("mask2",mask2)])

    
    print_table(anony_srcip_table, target)
    print_table(anony_dstip_table, target)

    
if __name__ == "__main__":
    main()
    
