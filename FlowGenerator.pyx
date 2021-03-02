from packet cimport packet_struct
cimport DataFlow
from flow cimport flow_struct
from libc.stdio cimport FILE, fopen, fclose, fwrite
from libc.stdlib cimport malloc, free
from PacketParser cimport parse_packet
from libc.string cimport strcpy, strcmp




cdef class FlowGenerator:
    """
    The main class to access and interact with FEX.
    
    The class processing packets via the process_packet function,
    which parses the packet by using the provided PacketParser 
    class and adding the packet to the corresponding data flow.

    This class allows a variation of options, which change the behaviour 
    of the class regarding resource usage and execution speed. This behaviour
    is defined by the provided attributes, which specify how the generated 
    features are returned to the user.


    Attributes
    ----------

    output_file: str, optional
        defines the filename and path of the output path. This value is required when
        the output_method 'file' is chosen. This attribute will be ignored when the 
        output_method 'return' is chosen.

    output_event: int, optional
        specifies when the features will be created. This value allows to either receive
        the features after every n-th packet or after the flow is finished.
            - 0: will create the features after the flow is finished. This happens either
                if a TCP packet has a fin-flag or after the timeout value is exceeded.
            - 1..n: will create additional features after the specified numbers of packets.
                This allows to analyse unfinished flows, but will also at latest create
                the features after the flow is finished, as described above. (default 0)

    flow_timeout: int, optional
        Specifies after how many microseconds a timeout takes place. A exceed of this value will
        finish the data flow but will not automatically create the corresponding features.
        Features creation caused by a timeout will be created when either the terminate_timeout_flows()
        or terminate_all_flows() function is called. (default 120000000 which equals 2 minutes)


    """

    # general needed datastructures
    cdef dict currentFlows

    # runtime specific attributes
    cdef long flow_timeout
    cdef long activity_timeout
    cdef int output_event
    cdef int min_packets_per_flow
    cdef bint ignore_min_size_on_fin

    cdef str output_file
    cdef FILE* output
    # runtime stats
    cdef int total_packets
    cdef int discarded_packets
    cdef int created_features_count

    def __cinit__(self, output_file=None, output_event=0, flow_timeout=120000000, activity_timeout=5000000, min_packets_per_flow=2, ignore_min_size_on_fin=True):
        
        self.currentFlows = {}

        self.flow_timeout = flow_timeout
        self.activity_timeout = activity_timeout
        self.output_event = output_event
        self.output_file = output_file
        self.min_packets_per_flow = min_packets_per_flow
        self.ignore_min_size_on_fin = ignore_min_size_on_fin        

        self.total_packets = 0
        self.discarded_packets = 0
        self.created_features_count = 0

        # TODO: Error handling for proper file handling
        # Produces seg fault if file does not exist
        if self.output_file:
            self.output = fopen(output_file.encode('UTF-8'), 'a')

        if self.output_file:
            self.write_header()


    cdef list add_packet_c(self, packet_struct packet):
        cdef DataFlow.DataFlow flow
        cdef bint flow_exists = False
        cdef list features = []
        cdef str flow_id
        cdef str fwd_id = packet.fwd_id.decode('UTF-8') 
        cdef str bwd_id = packet.bwd_id.decode('UTF-8') 

        # Check if flow already exists and determine flow direction
        if fwd_id in self.currentFlows.keys():
            flow_exists = True
            flow_id = fwd_id
        elif bwd_id in self.currentFlows.keys():
            flow_exists = True
            flow_id = bwd_id


        if flow_exists:
            flow = self.currentFlows[flow_id]


            if (packet.timestamp - flow.get_flow_start_time()) >= self.flow_timeout:
                # Timeout threshold is exceeded, generate features of existing dataflow and add new packet to a new dataflow

                if flow.get_packet_count() >= self.min_packets_per_flow:
                    features = flow.get_features()

                # remove that flow, as a new flow will be created after a timeout
                self.currentFlows.pop(flow_id)

                # Create new flow. The direction of the new flow is based on the previous flow.
                # Therefore the check_flow_direction compares the (previous) flow source ip with the new packet ip.
                # If both are equal the new flow uses the packet source and destination values as usually.
                # If both differ, the source and destination values of the packet get swapped, to remain information about who initialized the dataflow.
                
                if flow.check_flow_direction(packet.src) == 0:
                    flow = DataFlow.DataFlow(packet, True)
                else:
                    flow = DataFlow.DataFlow(packet, False)

                self.currentFlows[flow_id] = flow 

            elif packet.flag_fin == True:
                # Last Packet of data flow due to fin-flag (tcp only)
                # add packet, get features and end/remove dataflow after this step 
                flow.add_packet(packet)

                if (flow.get_packet_count() >= self.min_packets_per_flow) or self.ignore_min_size_on_fin:
                    features = flow.get_features()
                
                self.currentFlows.pop(flow_id)
            else:
                # New normal (not fin) packet for exisiting dataflow
                flow.add_packet(packet)
                self.currentFlows[flow_id] = flow

                # handle output event
                if self.output_event > 0:
                    if flow.get_packet_count() % self.output_event == 0:
                        features = flow.get_features()

        else:

            # New Flow is created. Therefore the direction is always forward
            flow = DataFlow.DataFlow(packet)
            self.currentFlows[fwd_id] = flow
            
        if len(features) > 0:
            if self.output_file:
                self.write_features(features)
                self.created_features_count += 1


        return features

    cpdef list perform_timeout_detection(self, long current_time):
        cdef DataFlow.DataFlow flow
        cdef list feature_list = []
        cdef list features = []

        for key in self.currentFlows.keys():
            flow = self.currentFlows[key]
            if (current_time - flow.get_flow_start_time()) > self.flow_timeout:
                if flow.get_packet_count() >= self.min_packets_per_flow:
                    features = flow.get_features()
                    feature_list.append(features)

                    if self.output_file:
                        if len(features) > 0:
                            self.write_features(features)
                            self.created_features_count += 1

        return feature_list


    cpdef list end_active_flow(self):
        cdef list feature_list = []
        for flow in self.currentFlows:
            if self.currentFlows[flow].get_packet_count() >= self.min_packets_per_flow:
                
                features = self.currentFlows[flow].get_features()
                feature_list.append(features)

                if self.output_file:
                    if len(features) > 0:
                        self.write_features(features)
                        self.created_features_count += 1
        return feature_list



    cdef void write_features(self, list features):
        my_features = ','.join(str(x) for x in features) + '\n'
        cdef char* write_output = <char *> malloc((len(my_features) +1) * sizeof(char))        
        strcpy(write_output, my_features.encode('UTF-8'))

        fwrite(<void *> &write_output[0], sizeof(char), len(my_features), self.output)
        free(write_output)


    cpdef void write_header(self):
        cdef char* header = "Flow ID,Timestamp,Src IP,Src Port,Dst IP,Dst Port,Protocol,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Fwd Pkt Len Max,Fwd Pkt Len Min,Fwd Pkt Len Mean,Fwd Pkt Len Std,Bwd Pkt Len Max,Bwd Pkt Len Min,Bwd Pkt Len Mean,Bwd Pkt Len Std,Flow Byts/s,Flow Pkts/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Tot,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Tot,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Len,Bwd Header Len,Fwd Pkts/s,Bwd Pkts/s,Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,Pkt Len Var,FIN Flag Cnt,SYN Flag Cnt,RST Flag Cnt,PSH Flag Cnt,ACK Flag Cnt,URG Flag Cnt,CWE Flag Count,ECE Flag Cnt,Down/Up Ratio,Pkt Size Avg,Fwd Seg Size Avg,Bwd Seg Size Avg,Fwd Byts/b Avg,Fwd Pkts/b Avg,Fwd Blk Rate Avg,Bwd Byts/b Avg,Bwd Pkts/b Avg,Bwd Blk Rate Avg,Subflow Fwd Pkts,Subflow Fwd Byts,Subflow Bwd Pkts,Subflow Bwd Byts,Init Fwd Win Byts,Init Bwd Win Byts,Fwd Act Data Pkts,Fwd Seg Size Min,Active Mean, Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min\n"
        fwrite(<void *> &header[0], sizeof(char), len(header), self.output)


    cpdef void close_file(self):
        if self.output:
            fclose(self.output)

    cpdef dict get_stats(self):
        return {
            'total_packets':self.total_packets,
            'discarded_packets':self.discarded_packets,
            'features_generated':self.created_features_count
        }


    cdef list process_packet_c(self, packet_bytes, timestamp):
        cdef packet_struct packet
        packet = parse_packet(packet_bytes, timestamp)

        # check if packet is valid (ipv4 with tcp, udp or icmp)
        if packet.protocol != -1:
            self.total_packets += 1
            return self.add_packet_c(packet)
        self.discarded_packets += 1

        return []


    def process_packet(self, packet_bytes, timestamp):
        return self.process_packet_c(packet_bytes, timestamp)
