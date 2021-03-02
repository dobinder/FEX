#ifndef __PACKET_H_
#define __PACKET_H_
#include <stdbool.h>

typedef struct packet_struct {
        char* fwd_id;
        char* bwd_id;
        char* src;
        char* dst;
        int src_port;
        int dst_port;
        int protocol;
        long timestamp;
        int payload_bytes;
        int tcp_window;
        int header_bytes;
        int payload_packet;
        bool flag_fin;
        bool flag_psh;
        bool flag_urg;
        bool flag_ece;
        bool flag_syn;
        bool flag_ack;
        bool flag_cwr;
        bool flag_rst;
} packet_struct; 
#endif //__PACKET_H_