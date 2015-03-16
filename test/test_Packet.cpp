#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "Packet check"
#include <commons/packet.h>
#include <iostream>
#include <boost/test/unit_test.hpp> //VERY IMPORTANT - include this last

BOOST_AUTO_TEST_CASE( cigarette ) {

    std::string test_packet = "1425226022!173074!01005e0000010024899c0fe4080046c00020000040000102426dc0a80101e0000001940400001164ee9b00000000";

    std::shared_ptr<network::packet> packet = network::packet::factory( test_packet );

    BOOST_CHECK( packet->isIPv4() );

    std::shared_ptr<network::IPv4packet> pkg_ipv4 = std::dynamic_pointer_cast<network::IPv4packet>( packet );

    BOOST_REQUIRE( pkg_ipv4 != nullptr );
    BOOST_CHECK( pkg_ipv4->getSenderIp().to_string() == "192.168.1.1" );
    BOOST_CHECK( pkg_ipv4->getTargetIp().to_string() == "224.0.0.1" );

}
