#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "Global check"
#include <boost/test/unit_test.hpp> //VERY IMPORTANT - include this last

BOOST_AUTO_TEST_CASE( base ) {
    BOOST_CHECK_EQUAL( 2+2, 4 );
}
