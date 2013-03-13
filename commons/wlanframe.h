/* 
 * TODO
 */

#ifndef WLANFRAME_H
#define	WLANFRAME_H

/** wlantype: 6 bit (2 bit for type, 4 bit for subtype) */
namespace wlantype {
    const uint8_t ASS_REQUEST           = 0x00;
    const uint8_t ASS_RESPONSE          = 0x01; 
    const uint8_t RASS_REQUEST          = 0x02;
    const uint8_t RASS_RESPONSE         = 0x03; 
    const uint8_t PROBE_REQUEST         = 0x04;
    const uint8_t PROBE_RESPONSE        = 0x05;
    const uint8_t BEACON                = 0x08;
    const uint8_t ATIM                  = 0x09;
    const uint8_t DISASS                = 0x0A;
    const uint8_t AUTH                  = 0x0B;
    const uint8_t DEAUTH                = 0x0C;
    const uint8_t DATA                  = 0x20;
}

namespace network {

    class wlanframe {
    public:
        wlanframe();
        wlanframe(const wlanframe& orig);
        virtual ~wlanframe();
    private:

    };

}

#endif	/* WLANFRAME_H */

