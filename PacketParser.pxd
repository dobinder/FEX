include "packet.pxd"

cpdef packet_struct parse_packet(unsigned char* payload, long timestamp)