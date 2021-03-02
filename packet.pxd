cdef extern from "packet.h":
    struct packet_struct:
        char* fwd_id
        char* bwd_id
        # char* flow_id
        # bint direction
        char* src
        char* dst
        int src_port
        int dst_port
        int protocol
        long timestamp
        int payload_bytes
        int tcp_window
        int header_bytes
        int payload_packet
        bint flag_fin
        bint flag_psh
        bint flag_urg
        bint flag_ece
        bint flag_syn
        bint flag_ack
        bint flag_cwr
        bint flag_rst