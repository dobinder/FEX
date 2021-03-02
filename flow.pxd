include "StatCounter.pxd"
include "FlagCounter.pxd"

cdef extern from "flow.h":
    ctypedef struct flow_struct:
        char flow_id[60]
        char src[60]
        char dst[60]
        
        int src_port
        int dst_port
        int protocol
        long flow_start_time
        long start_active_time
        long end_active_time
        int forward_bytes
        int backward_bytes
        int forward_header_bytes
        int backward_header_bytes
        
        stat_counter forward_packet_stats
        stat_counter backward_packet_stats

        bint is_bidirectional
        flag_counter flag_counter

        int act_data_pkt_forward
        int min_seg_size_forward
        int init_win_bytes_forward
        int init_win_bytes_backward

        long forward_bulk_duration
        int forward_bulk_packet_count
        int forward_bulk_size_total
        int forward_bulk_state_count
        int forward_bulk_packet_count_helper
        int forward_bulk_size_helper
        long forward_bulk_start_helper
        long forward_last_bulk_TS
        
        long backward_bulk_duration
        int backward_bulk_packet_count
        int backward_bulk_size_total
        int backward_bulk_state_count
        int backward_bulk_packet_count_helper
        int backward_bulk_size_helper
        long backward_bulk_start_helper
        long backward_last_bulk_TS

        bint forward_packet_received
        bint backward_packet_received
        
        stat_counter flow_iat
        stat_counter forward_iat
        stat_counter backward_iat
        stat_counter flow_length_stats
        stat_counter flow_active
        stat_counter flow_idle
        
        long flow_last_seen
        long forward_last_seen
        long backward_last_seen
        long sub_flow_last_packet_timestamp
        long sub_flow_ac_helper
        int sub_flow_count