from packet cimport packet_struct
from libc.stdlib cimport malloc, free
from libc.string cimport strcpy
from libc.stdio cimport sprintf


cpdef packet_struct parse_packet(unsigned char* payload, long timestamp): 
    cdef packet_struct packet = packet_struct("", "", "", "", 0, 0, -1, 0, 0, 0, 0, 0, False, False, False, False, False, False, False, False)
    
    cdef char src_addr[16] 
    cdef char dst_addr[16]
    cdef char fwd_id[49]
    cdef char bwd_id[49]

    cdef int src_port
    cdef int dst_port
    cdef int data_offset
    cdef int total_length
    cdef int ihl
    cdef int flags
    
    cdef int eth_protocol = ((((payload[12]) )) << 8) | (((payload[13])) >> 8)
    packet.timestamp = timestamp

    # check if packet is ip packet
    if eth_protocol == 8:
        return packet

    # check if ip packet is IPv4 packet
    if (payload[14] & 0xF0) >> 4 == 4:

        ihl = payload[14] & 0x0F

        sprintf(src_addr, "%i.%i.%i.%i", payload[26], payload[27], payload[28], payload[29])
        sprintf(dst_addr, "%i.%i.%i.%i", payload[30], payload[31], payload[32], payload[33])
        
        total_length = (payload[16]<<8) | payload[17] # Total length of packet in bytes

        
        if payload[23] == 6: # TCP
            packet.protocol = 6

            # In most cases IHL will be 5. Therefore we use this case as a default and treat only deviations differently.
            # By doing so we avoid additional unneccessary calculations for most cases. Same for UDP.
            if ihl == 5:
                src_port = (payload[34]<<8) | payload[35] 
                dst_port = (payload[36]<<8) | payload[37] 


                packet.src_port = src_port
                packet.dst_port = dst_port
                packet.tcp_window = (payload[48] << 8) | payload[49]


                flags =  payload[47]
                packet.flag_fin = flags & 1 
                packet.flag_syn = flags & 2
                packet.flag_rst = flags & 4
                packet.flag_psh = flags & 8
                packet.flag_ack = flags & 16
                packet.flag_urg = flags & 32
                packet.flag_ece = flags & 64
                packet.flag_cwr = flags & 128

                data_offset = payload[46]>>4

                packet.header_bytes = data_offset * 4
                packet.payload_bytes = total_length - ((data_offset + ihl) * (4))

            else:
                # TODO: Add handling for other IHL != 5
                pass    

            sprintf(fwd_id, "%s%s%s%s%d%s%d%s", src_addr, "-", dst_addr, "-", src_port, "-", dst_port, "-tcp");
            sprintf(bwd_id, "%s%s%s%s%d%s%d%s", dst_addr, "-", src_addr, "-", dst_port, "-", src_port, "-tcp");
        
        elif payload[23] == 17: # UDP

            if ihl == 5:
                packet.protocol = 17

                src_port = (payload[34]<<8) | payload[35]
                dst_port = (payload[36]<<8) | payload[37]
                packet.src_port = src_port
                packet.dst_port = dst_port

                udp_length = (payload[38]<<8) | payload[39] 

                packet.header_bytes = 8                 # length of udp header is always 8 bytes, as there are no optional fields
                packet.payload_bytes = udp_length -8    # total length - header length

                sprintf(fwd_id, "%s%s%s%s%d%s%d%s", src_addr, "-", dst_addr, "-", src_port, "-", dst_port, "-udp");
                sprintf(bwd_id, "%s%s%s%s%d%s%d%s", dst_addr, "-", src_addr, "-", dst_port, "-", src_port, "-udp");
            else:
                # TODO: Add handling for other IHL != 5
                print("UDP IHL != 5")
                pass
        elif payload[23] == 1:
            packet.protocol = 1
            sprintf(fwd_id, "%s%s%s%s", src_addr, "-", dst_addr, "-0-0-icmp");
            sprintf(bwd_id, "%s%s%s%s", dst_addr, "-", src_addr, "-0-0-icmp"); 

    else:   # Protocol is neither TCP or UDP, skip packet
        # packet struct gets returned with the initialized protocol = -1
        # The FlowGenerator object checks this value and therefore detects the packet nether UDP or TCP
        return packet
        
    
    packet.src = <char*> malloc (sizeof (char)*len(src_addr)+1)
    strcpy(packet.src, src_addr)
    packet.dst = <char*> malloc (sizeof (char)*len(dst_addr)+1)
    strcpy(packet.dst, dst_addr)
    
    packet.fwd_id = <char*> malloc (sizeof (char)*len(fwd_id)+1)
    strcpy(packet.fwd_id, fwd_id)
    packet.bwd_id = <char*> malloc (sizeof (char)*len(bwd_id)+1)
    strcpy(packet.bwd_id, bwd_id)
    

    return packet
