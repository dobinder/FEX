from pylibpcap.open import OpenPcap
from fextractor.FlowGenerator import FlowGenerator

# create a flow generator using FEX
# optionally pass output_file parameter to directly write into a file
generator = FlowGenerator(output_file='./output.csv')

# Use an arbitrary pcap reader to access packets
with OpenPcap("input_example.pcap", filters="") as f:
    for _, ts, pkt in f.read():
    	# process the packet by passing it to the generator
    	# optionally the features can be received and immediately processed
        generator.process_packet(pkt, ts)

# terminate all active flows
generator.end_active_flow()
