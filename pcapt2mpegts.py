#!/usr/bin/python
from scapy.all import * 
import os
import time
import argparse

def main():
    parser = argparse.ArgumentParser(description="""pcap2mpegts extracts MPEG2TS stream from pcap files \
            capture (tcpdump/wireshark). Input *.pcap must contain single stream""")
    parser.add_argument('-i', required=True, help='Input file. Must be valid pcap dump.', dest='input', default=None, action='store', type=str)
    parser.add_argument('-o', required=True, help='Output file to write TS.', action = 'store', dest='output', type=str)
    parser.add_argument('-t', required=True, help='Type of stream in pcap file. Can be raw or srt.', action = 'store', dest='stream_type', type=str)
    args = parser.parse_args()

    pcap_path = args.input 
    ts_path = args.output 
    file_size = os.path.getsize(pcap_path)
    print(f"Loadinig file into memory, thats may take sometime, filesize: {file_size} bytes")
    print(f"Done...\nWriting packets to {ts_path} file")
    # here create file or erase if it already exist
    try: 
        open(ts_path, 'w').close()
    except Exception as e:
        print("Error:", e)
        return -1


    with open(ts_path, 'ab') as fd:
        if args.stream_type == 'raw':
            for packet in PcapReader(pcap_path):
                fd.write(bytes(packet[UDP].payload))
        if args.stream_type == 'srt':
            for packet in PcapReader(pcap_path):
                # get only DATA packets
                if (bytes(packet[UDP].payload)[0] >> 7) & 1  == 0: 
                        # skip header
                        fd.write(bytes(packet[UDP].payload)[16:])

if __name__ == "__main__":
    main()
