from scapy.all import sniff, Raw
import sys

proj_id = None

def process_packet(packet):
    if Raw in packet:
        if proj_id in packet[Raw].load and 'payload' in packet[Raw].load:
            print str(packet[Raw].load).split('payload')[1][3:-3]


def main(p_id):
     global proj_id
     proj_id = p_id 
     sniff(filter='port 9311', prn=process_packet)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Please provide project id"
        print "Syntax : python sniff_secret.py <proj_id>"
    else:
        main(sys.argv[1])
