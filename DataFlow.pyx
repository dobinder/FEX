from packet cimport packet_struct
from flow cimport flow_struct
from StatCounter cimport stat_counter
from FlagCounter cimport flag_counter
cimport StatisticsCounter
cimport cython
from libc.math cimport sqrt
from libc.string cimport strcpy, strcmp
from libc.limits cimport INT_MAX

cdef class DataFlow:

    def __cinit__(self, packet_struct packet, bint direction=True):

        self.flow = flow_struct(
                protocol = packet.protocol,
                
                is_bidirectional = True,
                
                forward_bytes  = 0,
                end_active_time = 0,
                backward_bytes = 0,
                forward_header_bytes = 0,
                backward_header_bytes = 0,
                
                flow_start_time = packet.timestamp,
                start_active_time = packet.timestamp,
                flow_last_seen = packet.timestamp,
                forward_last_seen = 0,
                backward_last_seen = 0,
                sub_flow_last_packet_timestamp = -1,
                
                flag_counter = flag_counter(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),

                act_data_pkt_forward = 0, # Packets that contain a payload, not only init
                min_seg_size_forward = 0,
                init_win_bytes_forward = 0,
                init_win_bytes_backward = 0,

                forward_bulk_duration = 0,
                forward_bulk_packet_count = 0,
                forward_bulk_size_total = 0,
                forward_bulk_state_count = 0,
                forward_bulk_packet_count_helper = 0,
                forward_bulk_start_helper = 0,
                forward_bulk_size_helper = 0,
                forward_last_bulk_TS = 0,
            
                backward_bulk_duration = 0,
                backward_bulk_packet_count = 0,
                backward_bulk_size_total = 0,
                backward_bulk_state_count = 0,
                backward_bulk_packet_count_helper = 0,
                backward_bulk_start_helper = 0,
                backward_bulk_size_helper = 0,
                backward_last_bulk_TS = 0,
            
                forward_packet_stats = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                backward_packet_stats = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                flow_iat = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                forward_iat = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                backward_iat = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                flow_length_stats = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                flow_active = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),
                flow_idle = stat_counter(0, 0, 0, 0, 0, INT_MAX, 0),

                forward_packet_received = False,
                backward_packet_received = False,
            
                sub_flow_count = 0,
                sub_flow_ac_helper = -1
            )

        # Normal case: constructor gets called only packet as parameter
        if direction:
            strcpy(self.flow.src, packet.src)
            strcpy(self.flow.dst, packet.dst)
            self.flow.src_port = packet.src_port
            self.flow.dst_port = packet.dst_port
        else:
        # Special case for timeout events: constructor gets called with parameters from timeout flow
        # This ensures that the direction of the previous flow is maintained.
            strcpy(self.flow.src, packet.dst)
            strcpy(self.flow.dst, packet.src)
            self.flow.src_port = packet.dst_port
            self.flow.dst_port = packet.src_port
        
        # Calculate the flow_id based on the direction of the flow
        if strcmp(packet.src, self.flow.src) == 0:
            strcpy(self.flow.flow_id, packet.fwd_id)
        else:
            strcpy(self.flow.flow_id, packet.bwd_id)

        self.first_packet(packet)


    cpdef long get_flow_start_time(self):
        return self.flow.flow_start_time


    cpdef int get_packet_count(self):
        return self.packet_count()


    cdef bint check_flow_direction(self, char* packet_src_addr):
        return strcmp(self.flow.src, packet_src_addr)


    cdef void first_packet(self, packet_struct packet):
        self.update_flow_bulk(packet)
        self.detect_and_update_sublfows(packet)
        self.check_flags(packet)

        StatisticsCounter.update(&self.flow.flow_length_stats, packet.payload_bytes)

        if strcmp(packet.src, self.flow.src) == 0:
            self.flow.min_seg_size_forward = packet.header_bytes
            self.flow.init_win_bytes_forward = packet.tcp_window

            StatisticsCounter.update(&self.flow.forward_packet_stats ,packet.payload_bytes)
            self.flow.forward_header_bytes = packet.header_bytes
            self.flow.forward_last_seen = packet.timestamp
            self.flow.forward_bytes += packet.payload_bytes
            self.flow.forward_packet_received = True
            
            if packet.flag_psh:
                self.flow.flag_counter.psh_forward += 1     
            if packet.flag_urg:
                self.flow.flag_counter.urg_forward += 1
        else:
            self.flow.init_win_bytes_backward = packet.tcp_window
            StatisticsCounter.update(&self.flow.backward_packet_stats, packet.payload_bytes)
            self.flow.backward_header_bytes = packet.header_bytes
            self.flow.backward_last_seen = packet.timestamp
            self.flow.backward_bytes += packet.payload_bytes
            self.flow.backward_packet_received = True

            if packet.flag_psh:
                self.flow.flag_counter.psh_backward += 1
            if packet.flag_urg:
                self.flow.flag_counter.urg_backward += 1


    cpdef void add_packet(self, packet_struct packet):
        self.update_flow_bulk(packet)
        self.detect_and_update_sublfows(packet)
        self.check_flags(packet)
        
        cdef long current_time = packet.timestamp
        
        StatisticsCounter.update(&self.flow.flow_length_stats, packet.payload_bytes)

        if strcmp(packet.src, self.flow.src) == 0:

            if packet.payload_bytes >= 1:
                self.flow.act_data_pkt_forward +=1 
            
            StatisticsCounter.update(&self.flow.forward_packet_stats ,packet.payload_bytes)

            self.flow.forward_header_bytes += packet.header_bytes
            self.flow.forward_bytes += packet.payload_bytes

            if self.flow.forward_packet_received:
                StatisticsCounter.update(&self.flow.forward_iat, current_time - self.flow.forward_last_seen)

            self.flow.forward_last_seen = current_time
            self.flow.min_seg_size_forward = min(packet.header_bytes,  self.flow.min_seg_size_forward)
            self.flow.forward_packet_received = True

        else:

            StatisticsCounter.update(&self.flow.backward_packet_stats, packet.payload_bytes)

            self.flow.backward_header_bytes += packet.header_bytes
            self.flow.backward_bytes += packet.payload_bytes

            if self.flow.backward_packet_received:
                StatisticsCounter.update(&self.flow.backward_iat, current_time - self.flow.backward_last_seen)                

            self.flow.backward_last_seen = current_time
            self.flow.backward_packet_received = True

        StatisticsCounter.update(&self.flow.flow_iat, packet.timestamp - self.flow.flow_last_seen)
        self.flow.flow_last_seen = packet.timestamp


    cdef void update_flow_bulk(self, packet_struct packet):
        if strcmp(packet.src, self.flow.src) == 0:
            self.update_forward_bulk(packet, self.flow.backward_last_bulk_TS)
        else:
            self.update_backward_bulk(packet, self.flow.forward_last_bulk_TS)


    cdef void update_forward_bulk(self, packet_struct packet, long timestamp_last_bulk):
        cdef int size = packet.payload_bytes
        cdef long pct_ts = packet.timestamp

        if timestamp_last_bulk > self.flow.forward_bulk_start_helper:
            self.flow.forward_bulk_start_helper = 0
        if size <= 0:
            return

        if self.flow.forward_bulk_start_helper == 0:
            self.flow.forward_bulk_start_helper = pct_ts
            self.flow.forward_bulk_packet_count_helper = 1
            self.flow.forward_bulk_size_helper = size
            self.flow.forward_last_bulk_TS = pct_ts
        else:
            if ((pct_ts - self.flow.forward_last_bulk_TS) / 1000000) >1.0:
                self.flow.forward_bulk_start_helper = pct_ts
                self.flow.forward_last_bulk_TS = pct_ts
                self.flow.forward_bulk_packet_count_helper = 1
                self.flow.forward_bulk_size_helper = size
            else: #add to bulk:
                self.flow.forward_bulk_packet_count_helper += 1
                self.flow.forward_bulk_size_helper += size
                # New Bulk
                if self.flow.forward_bulk_packet_count_helper == 4:
                    self.flow.forward_bulk_state_count += 1
                    self.flow.forward_bulk_packet_count += self.flow.forward_bulk_packet_count_helper
                    self.flow.forward_bulk_size_total += self.flow.forward_bulk_size_helper
                    self.flow.forward_bulk_duration += pct_ts - self.flow.forward_bulk_start_helper
                ## Continuation of existing bulk
                elif self.flow.forward_bulk_packet_count_helper > 4:
                    self.flow.forward_bulk_packet_count += 1
                    self.flow.forward_bulk_size_total += size
                    self.flow.forward_bulk_duration += pct_ts - self.flow.forward_last_bulk_TS
                self.flow.forward_last_bulk_TS = pct_ts


    cdef void update_backward_bulk(self, packet_struct packet, long timestamp_last_bulk):
        cdef int size = packet.payload_bytes
        cdef long pct_ts = packet.timestamp

        if timestamp_last_bulk > self.flow.backward_bulk_start_helper:
            self.flow.backward_bulk_start_helper = 0
        if size <= 0:
            return

        if self.flow.backward_bulk_start_helper == 0:
            self.flow.backward_bulk_start_helper = pct_ts
            self.flow.backward_bulk_packet_count_helper = 1
            self.flow.backward_bulk_size_helper = size
            self.flow.backward_last_bulk_TS = pct_ts
        else:
            if ((pct_ts - self.flow.backward_last_bulk_TS) / 1000000) >1.0:
                self.flow.backward_bulk_start_helper = pct_ts
                self.flow.backward_last_bulk_TS = pct_ts
                self.flow.backward_bulk_packet_count_helper = 1
                self.flow.backward_bulk_size_helper = size
            else: #add to bulk:
                self.flow.backward_bulk_packet_count_helper += 1
                self.flow.backward_bulk_size_helper += size
                # New Bulk
                if self.flow.backward_bulk_packet_count_helper == 4:
                    self.flow.backward_bulk_state_count += 1
                    self.flow.backward_bulk_packet_count += self.flow.backward_bulk_packet_count_helper
                    self.flow.backward_bulk_size_total += self.flow.backward_bulk_size_helper
                    self.flow.backward_bulk_duration += pct_ts - self.flow.backward_bulk_start_helper
                ## Continuation of existing bulk
                elif self.flow.backward_bulk_packet_count_helper > 4:
                    self.flow.backward_bulk_packet_count += 1
                    self.flow.backward_bulk_size_total += size
                    self.flow.backward_bulk_duration += pct_ts - self.flow.backward_last_bulk_TS
                self.flow.backward_last_bulk_TS = pct_ts


    cdef void detect_and_update_sublfows(self, packet_struct packet):
        if self.flow.sub_flow_last_packet_timestamp == -1:
            self.flow.sub_flow_last_packet_timestamp = packet.timestamp
            self.flow.sub_flow_ac_helper = packet.timestamp

        if (packet.timestamp - (self.flow.sub_flow_last_packet_timestamp/1000000)) > 1.0:
            self.flow.sub_flow_count += 1
            self.update_active_and_idle_time(packet.timestamp - self.flow.sub_flow_last_packet_timestamp, 5000000) # TODO: set activity timeout value here
            self.flow.sub_flow_ac_helper = packet.timestamp

        self.flow.sub_flow_last_packet_timestamp = packet.timestamp


    cpdef void update_active_and_idle_time(self, long current_time, int threshold):
        if (current_time - self.flow.end_active_time) > threshold:
            if (self.flow.end_active_time - self.flow.start_active_time) > 0:
                StatisticsCounter.update(&self.flow.flow_active, self.flow.end_active_time - self.flow.start_active_time)

            StatisticsCounter.update(&self.flow.flow_idle, current_time - self.flow.end_active_time)

            self.flow.start_active_time = current_time
            self.flow.end_active_time = current_time
        else:
            self.flow.end_active_time = current_time


    cdef void check_flags(self, packet_struct packet):
        if packet.flag_fin:
            self.flow.flag_counter.fin += 1
        if packet.flag_syn:
            self.flow.flag_counter.syn += 1
        if packet.flag_rst:
            self.flow.flag_counter.rst += 1
        if packet.flag_psh:
            self.flow.flag_counter.psh += 1
        if packet.flag_ack:
            self.flow.flag_counter.ack += 1
        if packet.flag_urg:
            self.flow.flag_counter.urg += 1
        if packet.flag_cwr:
            self.flow.flag_counter.cwr += 1
        if packet.flag_ece:
            self.flow.flag_counter.ece += 1


    ##### Feature Extraction #####

        # Helper Functions #
    @cython.cdivision(True)
    cdef float get_sub_flow_forward_bytes(self):
        if self.flow.sub_flow_count <= 0:
            return 0
        return self.flow.forward_bytes / self.flow.sub_flow_count

    @cython.cdivision(True)
    cdef float get_sub_flow_forward_packets(self):
        if self.flow.sub_flow_count <= 0:
            return 0
        return self.flow.forward_packet_stats.count / self.flow.sub_flow_count

    @cython.cdivision(True)
    cdef float get_sub_flow_backward_bytes(self):
        if self.flow.sub_flow_count <= 0:
            return 0
        return self.flow.backward_bytes / self.flow.sub_flow_count

    @cython.cdivision(True)
    cdef float get_sub_flow_backward_packets(self):
        if self.flow.sub_flow_count <= 0:
            return 0
        return self.flow.backward_packet_stats.count / self.flow.sub_flow_count

    @cython.cdivision(True)
    cdef float get_forward_packets_per_second(self):
        cdef float duration = self.flow.flow_last_seen - self.flow.flow_start_time
        if duration > 0:
            return self.flow.forward_packet_stats.count / (duration/1000000)
        return 0

    @cython.cdivision(True)
    cdef float get_backward_packets_per_second(self):
        cdef float duration = self.flow.flow_last_seen - self.flow.flow_start_time
        if duration > 0:
            return self.flow.backward_packet_stats.count / (duration/1000000)
        return 0

    @cython.cdivision(True)
    cdef float get_down_up_ratio(self):
        if self.flow.forward_packet_stats.count > 0:
            return self.flow.backward_packet_stats.count / self.flow.forward_packet_stats.count

    @cython.cdivision(True)
    cdef float get_avg_package_size(self):
        cdef int packet_count = self.packet_count()
        if packet_count > 0:
            return self.flow.flow_length_stats.sum_val / packet_count
        return 0

    @cython.cdivision(True)
    cdef float forward_avg_segment_size(self):
        if self.flow.forward_packet_stats.count != 0:
            return self.flow.forward_packet_stats.sum_val / self.flow.forward_packet_stats.count
        return 0

    @cython.cdivision(True)
    cdef float backward_avg_segment_size(self):
        if self.flow.backward_packet_stats.count != 0:
            return self.flow.backward_packet_stats.sum_val / self.flow.backward_packet_stats.count
        return 0

    @cython.cdivision(True)
    cdef float forward_bulk_duration_in_second(self):
        return float(self.flow.forward_bulk_duration / 1000000.0)

    # Client average bytes per bulk
    @cython.cdivision(True)
    cdef float forward_avg_bytes_per_bulk(self):
        if self.flow.forward_bulk_state_count != 0:
            return self.flow.forward_bulk_size_total / self.flow.forward_bulk_state_count
        return 0

    # Client average packets per bulk
    @cython.cdivision(True)
    cdef float forward_avg_packets_per_bulk(self):
        if self.flow.forward_bulk_state_count != 0:
            return self.flow.forward_bulk_packet_count / self.flow.forward_bulk_state_count
        return 0

    # Client average bulk rate
    @cython.cdivision(True)
    cdef float forward_avg_bulk_rate(self):
        cdef float duration  = self.forward_bulk_duration_in_second()
        if duration != 0:
            return self.flow.forward_bulk_size_total / duration
        return 0

    cdef float backward_bulk_duration_in_second(self):
        return float(self.flow.backward_bulk_duration / 1000000.0)

    # Server average bytes per bulk
    @cython.cdivision(True)
    cdef float backward_avg_bytes_per_bulk(self):
        if self.flow.backward_bulk_state_count != 0:
            return self.flow.backward_bulk_size_total / self.flow.backward_bulk_state_count
        return 0

    # Server average packets per bulk
    @cython.cdivision(True)
    cdef float backward_avg_packets_per_bulk(self):
        if self.flow.backward_bulk_state_count != 0:
            return self.flow.backward_bulk_packet_count / self.flow.backward_bulk_state_count
        return 0

    # Server average bulk rate
    @cython.cdivision(True)
    cdef float backward_avg_bulk_rate(self):
        cdef float duration = self.backward_bulk_duration_in_second()
        if duration > 0:
            return self.flow.backward_bulk_size_total / duration
        return 0

    cdef float get_flow_duration(self):
        return self.flow.flow_last_seen - self.flow.flow_start_time

    @cython.cdivision(True)
    cdef float flow_bytes_per_second(self):
        cdef float duration = self.get_flow_duration()
        if duration != 0:
            return (self.flow.forward_bytes + self.flow.backward_bytes) / (duration/1000000)
        return 0

    @cython.cdivision(True)
    cdef float flow_packets_per_second(self):
        cdef float duration = self.get_flow_duration()
        if duration != 0:
            return self.packet_count() / (duration / 1000000)
        return 0

    cdef int packet_count(self):
        return self.flow.forward_packet_stats.count + self.flow.backward_packet_stats.count


    cpdef get_features(self):
        return [
            self.flow.flow_id.decode('ascii'),                      #1
            self.flow.flow_start_time,              #7
            self.flow.src.decode('ascii'),                          #2
            self.flow.src_port,                     #3
            self.flow.dst.decode('ascii'),                          #4
            self.flow.dst_port,                     #5
            self.flow.protocol,                     #6
            
            self.get_flow_duration(),               #8
            
            self.flow.forward_packet_stats.count,   #9
            self.flow.backward_packet_stats.count,  #10
            self.flow.forward_packet_stats.sum_val, #11
            self.flow.backward_packet_stats.sum_val,#12
            
            self.flow.forward_packet_stats.max_val, #13
            self.flow.forward_packet_stats.min_val if self.flow.forward_packet_stats.min_val != INT_MAX else 0, #14
            self.flow.forward_packet_stats.mean,    #15
            sqrt(self.flow.forward_packet_stats.variance), #16
            
            self.flow.backward_packet_stats.max_val,#17
            self.flow.backward_packet_stats.min_val if self.flow.backward_packet_stats.min_val != INT_MAX else 0, #18
            self.flow.backward_packet_stats.mean,   #19
            sqrt(self.flow.backward_packet_stats.variance), #20
            
            self.flow_bytes_per_second(),           #21
            self.flow_packets_per_second(),         #22
            
            self.flow.flow_iat.mean,                #23
            sqrt(self.flow.flow_iat.variance),      #24
            self.flow.flow_iat.max_val,             #25
            self.flow.flow_iat.min_val if self.flow.flow_iat.min_val != INT_MAX else 0, # 26
            
            self.flow.forward_iat.sum_val,          #27
            self.flow.forward_iat.mean,             #28
            sqrt(self.flow.forward_iat.variance),   #29
            self.flow.forward_iat.max_val,          #30
            self.flow.forward_iat.min_val if self.flow.forward_iat.min_val != INT_MAX else 0, #31

            self.flow.backward_iat.sum_val,          #32
            self.flow.backward_iat.mean,             #33
            sqrt(self.flow.backward_iat.variance),   #34
            self.flow.backward_iat.max_val,          #35
            self.flow.backward_iat.min_val if self.flow.backward_iat.min_val != INT_MAX else 0, # 36

            self.flow.flag_counter.psh_forward,      #37
            self.flow.flag_counter.psh_backward,     #38
            self.flow.flag_counter.urg_forward,      #39
            self.flow.flag_counter.urg_backward,     #40

            self.flow.forward_header_bytes,          #41
            self.flow.backward_header_bytes,         #42
            self.get_forward_packets_per_second(),    #43
            self.get_backward_packets_per_second(),   #44

            self.flow.flow_length_stats.min_val if self.flow.flow_length_stats.min_val != INT_MAX else 0,        #45
            self.flow.flow_length_stats.max_val,        #46
            self.flow.flow_length_stats.mean,           #47
            sqrt(self.flow.flow_length_stats.variance), #48
            self.flow.flow_length_stats.variance,       #49

            self.flow.flag_counter.fin,             #50
            self.flow.flag_counter.syn,             #51
            self.flow.flag_counter.rst,             #52
            self.flow.flag_counter.psh,             #53
            self.flow.flag_counter.ack,             #54
            self.flow.flag_counter.urg,             #55
            self.flow.flag_counter.cwr,             #56
            self.flow.flag_counter.ece,             #57

            self.get_down_up_ratio(),               #58
            self.get_avg_package_size(),            #59
            self.forward_avg_segment_size(),        #60
            self.backward_avg_segment_size(),       #61
            #self.flow.forward_header_bytes,          #62 -> duplicate of 42

            self.forward_avg_bytes_per_bulk(),      #63
            self.forward_avg_packets_per_bulk(),    #64
            self.forward_avg_bulk_rate(),           #65

            self.backward_avg_bytes_per_bulk(),     #66
            self.backward_avg_packets_per_bulk(),   #67
            self.backward_avg_bulk_rate(),          #68

            self.get_sub_flow_forward_packets(),    #69
            self.get_sub_flow_forward_bytes(),     #70
            self.get_sub_flow_backward_packets(),   #71
            self.get_sub_flow_backward_bytes(),     #72

            self.flow.init_win_bytes_forward,       #73
            self.flow.init_win_bytes_backward,      #74
            self.flow.act_data_pkt_forward,         #75
            self.flow.min_seg_size_forward,         #76

            self.flow.flow_active.mean,             #77
            sqrt(self.flow.flow_active.variance),   #78
            self.flow.flow_active.max_val,          #79
            self.flow.flow_active.min_val if self.flow.flow_active.min_val != INT_MAX else 0, #80

            self.flow.flow_idle.mean,               #81
            sqrt(self.flow.flow_idle.variance),     #82
            self.flow.flow_idle.max_val,            #83
            self.flow.flow_idle.min_val if self.flow.flow_idle.min_val != INT_MAX else 0 #84
        ]
