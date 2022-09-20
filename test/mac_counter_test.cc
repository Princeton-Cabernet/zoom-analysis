
#include <catch.h>
#include "lib/mac_counter.h"

TEST_CASE("mac_counter: computes the current overall count from a mac addr", "[mac_counter]") {

    SECTION("without wraparound") {

        mac_counter c;

        c.add(net::eth::str_to_addr("00:00:01:16:06:e2")); // 18220770
        CHECK(c.count() == 18220770ul);
        c.add(net::eth::str_to_addr("00:00:01:16:14:a3")); // 18224291
        CHECK(c.count() == 18224291ul);
        c.add(net::eth::str_to_addr("00:00:01:16:22:99")); // 18227865
        CHECK(c.count() == 18227865ul);

        CHECK(c.discard_count() == 0);
    }

    SECTION("with wraparound") {

        mac_counter c;

        c.add(net::eth::str_to_addr("00:00:ff:ff:fd:32")); // 4294966578
        CHECK(c.count() == 4294966578ul);
        c.add(net::eth::str_to_addr("00:00:ff:ff:ff:1d")); // 4294967069
        CHECK(c.count() == 4294967069ul);
        c.add(net::eth::str_to_addr("00:00:00:00:00:87")); //        135
        CHECK(c.count() == (0xfffffffful + 135ul));

        CHECK(c.discard_count() == 0);
    }

    SECTION("with reordering #1") {

        mac_counter c;

        c.add(net::eth::str_to_addr("00:00:ff:ff:fd:f3")); // 3543378431
        CHECK(c.count() == 4294966771ul);
        c.add(net::eth::str_to_addr("00:00:00:00:00:39")); //         57
        CHECK(c.count() == (0xfffffffful + 57ul));
        c.add(net::eth::str_to_addr("00:00:ff:ff:ff:f1")); //  4294967281
        CHECK(c.count() == (0xfffffffful + 57ul));
        c.add(net::eth::str_to_addr("00:00:00:00:01:fe")); //         510
        CHECK(c.count() == (0xfffffffful + 510ul));

        CHECK(c.discard_count() == 1);
    }

    SECTION("with reordering #2") {

        mac_counter c;

        c.add(net::eth::str_to_addr("00:00:00:00:00:10")); // 10
        CHECK(c.count() == 16ul);
        c.add(net::eth::str_to_addr("00:00:00:00:00:08")); //  8
        CHECK(c.count() == 16ul);


        CHECK(c.discard_count() == 1);

    }
}
