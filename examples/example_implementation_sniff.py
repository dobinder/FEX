from pylibpcap.pcap import sniff
from fextractor.FlowGenerator import FlowGenerator

# create a flow generator using FEX
# optionally pass output_file parameter to directly write into a file
generator = FlowGenerator(output_file='./output.csv') 

try:
	# Use an arbitrary network sniffer to access packets
    for _, ts, pkt in sniff("eth0"):
    	# process the packet by passing it to the generator
    	# optionally the features can be received and immediately processed
        features = generator.process_packet(pkt, ts)

except KeyboardInterrupt:
	# terminate all active flows
    generator.end_active_flow()