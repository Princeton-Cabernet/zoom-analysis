
#ifndef ZOOM_ANALYSIS_ZOOM_NETS_H
#define ZOOM_ANALYSIS_ZOOM_NETS_H

#include "net.h"

#include <algorithm>
#include <vector>

namespace zoom {

    class nets {

    public:

        static bool match(const uint32_t ip) {

            if (std::any_of(NETS.begin(), NETS.end(), [&ip](const auto& ip_mask) {
                return ip_mask.match(ip);
            })) return true;

            return false;
        }

        // addresses taken from:
        // https://support.zoom.us/hc/en-us/articles/
        //   201362683-Network-firewall-or-proxy-server-settings-for-Zoom

        // last update to list: Apr. 26, 2022

        static inline const std::vector<net::ipv4_mask> NETS = {
                { net::ipv4::str_to_addr("3.7.35.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.21.137.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.22.11.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("3.23.93.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("3.25.41.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.25.42.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.25.49.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("3.80.20.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.96.19.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("3.101.32.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.101.52.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.104.34.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.120.121.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.127.194.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.208.72.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.211.241.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.235.69.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.235.82.0"), ~(~uint32_t(0) >> 23) },
                { net::ipv4::str_to_addr("3.235.71.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.235.72.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.235.73.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("3.235.96.0"), ~(~uint32_t(0) >> 23) },
                { net::ipv4::str_to_addr("4.34.125.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("4.35.64.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("8.5.128.0"), ~(~uint32_t(0) >> 23) },
                { net::ipv4::str_to_addr("13.52.6.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("13.52.146.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("18.157.88.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("18.205.93.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("20.203.158.80"), ~(~uint32_t(0) >> 28) },
                { net::ipv4::str_to_addr("20.203.190.192"), ~(~uint32_t(0) >> 26) },
                { net::ipv4::str_to_addr("50.239.202.0"), ~(~uint32_t(0) >> 23) },
                { net::ipv4::str_to_addr("50.239.204.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("52.61.100.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("52.202.62.192"), ~(~uint32_t(0) >> 26) },
                { net::ipv4::str_to_addr("52.215.168.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("64.125.62.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("64.211.144.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("64.224.32.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("65.39.152.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("69.174.57.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("69.174.108.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("99.79.20.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("101.36.167.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("103.122.166.0"), ~(~uint32_t(0) >> 23) },
                { net::ipv4::str_to_addr("111.33.115.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("111.33.181.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("115.110.154.192"), ~(~uint32_t(0) >> 26) },
                { net::ipv4::str_to_addr("115.114.56.192"), ~(~uint32_t(0) >> 26) },
                { net::ipv4::str_to_addr("115.114.115.0"), ~(~uint32_t(0) >> 26) },
                { net::ipv4::str_to_addr("115.114.131.0"), ~(~uint32_t(0) >> 26) },
                { net::ipv4::str_to_addr("120.29.148.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("129.151.0.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("129.151.40.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("129.151.48.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("129.159.0.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("129.159.160.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("129.159.208.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("130.61.164.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("134.224.0.0"), ~(~uint32_t(0) >> 16) },
                { net::ipv4::str_to_addr("140.238.128.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("140.238.232.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("144.195.0.0"), ~(~uint32_t(0) >> 16) },
                { net::ipv4::str_to_addr("147.124.96.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("149.137.0.0"), ~(~uint32_t(0) >> 17) },
                { net::ipv4::str_to_addr("150.230.224.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("152.67.20.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("152.67.118.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("152.67.168.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("152.67.180.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("152.67.184.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("152.67.240.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("152.70.224.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("156.45.0.0"), ~(~uint32_t(0) >> 17) },
                { net::ipv4::str_to_addr("158.101.64.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("158.101.184.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("160.1.56.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("161.199.136.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("162.12.232.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("162.255.36.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("165.254.88.0"), ~(~uint32_t(0) >> 23) },
                { net::ipv4::str_to_addr("166.108.64.0"), ~(~uint32_t(0) >> 18) },
                { net::ipv4::str_to_addr("168.138.16.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("168.138.48.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("168.138.56.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("168.138.72.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("168.138.74.0"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("168.138.80.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("168.138.96.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("168.138.116.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("168.138.244.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("170.114.0.0"), ~(~uint32_t(0) >> 16) },
                { net::ipv4::str_to_addr("173.231.80.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("192.204.12.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("193.122.16.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("193.122.32.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("193.122.208.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("193.122.224.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("193.122.240.0"), ~(~uint32_t(0) >> 20) },
                { net::ipv4::str_to_addr("193.123.0.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("193.123.40.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("193.123.128.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("193.123.168.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("193.123.192.0"), ~(~uint32_t(0) >> 19) },
                { net::ipv4::str_to_addr("198.251.128.0"), ~(~uint32_t(0) >> 17) },
                { net::ipv4::str_to_addr("202.177.207.128"), ~(~uint32_t(0) >> 27) },
                { net::ipv4::str_to_addr("204.80.104.0"), ~(~uint32_t(0) >> 21) },
                { net::ipv4::str_to_addr("204.141.28.0"), ~(~uint32_t(0) >> 22) },
                { net::ipv4::str_to_addr("206.247.0.0"), ~(~uint32_t(0) >> 16) },
                { net::ipv4::str_to_addr("207.226.132.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("209.9.211.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("209.9.215.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("213.19.144.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("213.19.153.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("213.244.140.0"), ~(~uint32_t(0) >> 24) },
                { net::ipv4::str_to_addr("221.122.88.64"), ~(~uint32_t(0) >> 27) },
                { net::ipv4::str_to_addr("221.122.88.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("221.122.89.128"), ~(~uint32_t(0) >> 25) },
                { net::ipv4::str_to_addr("221.123.139.192"), ~(~uint32_t(0) >> 27) }
        };
    };
}

#endif
