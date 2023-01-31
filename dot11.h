#pragma once
#include <cstdint>
#include "mac.h"

#define SUBTYPE_DEAUTH 0xc;
#define SUBTYPE_AUTH 0xb;

struct Dot11
{
    uint8_t     version:2;
    uint8_t     type:2;
    uint8_t     subtype:4;
    uint8_t     flags;
    uint16_t    duration;
    Mac         receiver;
    Mac         transmitter;
    Mac         bssid;
    uint16_t    fragSeqNum;
};