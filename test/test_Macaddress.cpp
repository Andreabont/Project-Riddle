#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "Mac address check"
#include "../commons/macaddress.h"
#include <boost/test/unit_test.hpp> //VERY IMPORTANT - include this last

BOOST_AUTO_TEST_CASE( mac_address_eq ) {
    network::mac_address a("AA:AA:AA:AA:AA:AA");
    network::mac_address b("AA:AA:AA:AA:AA:AA");
    BOOST_CHECK( a == b );
}

BOOST_AUTO_TEST_CASE( mac_address_neq ) {
    network::mac_address a("AA:AA:AA:AA:AA:AA");
    network::mac_address b("BB:BB:BB:BB:BB:BB");
    BOOST_CHECK( a != b );
}

BOOST_AUTO_TEST_CASE( mac_address_io ) {
    network::mac_address a("aa:aa:aa:aa:aa:aa");
    BOOST_CHECK_EQUAL( a.to_string(), "aa:aa:aa:aa:aa:aa" );
}