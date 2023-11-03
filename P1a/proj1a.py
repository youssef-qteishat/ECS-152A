import dpkt
import sys
import datetime

def parse_pcap(pcap_file):
    http_count = 0
    https_count = 0
    FTP_count = 0
    ICMP_count = 0
    SSH_count = 0

    # Use context manager for file operations
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for timestamp, data in pcap:
            try:
                dest_ip = dpkt.utils.inet_to_str(ip.dst)
                print(dest_ip)
                eth = dpkt.ethernet.Ethernet(data)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                ip = eth.data
                if isinstance(ip.data, dpkt.icmp.ICMP):
                    ICMP_count += 1

                # Check for TCP in the transport layer
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    # # Skip if there is no application layer data
                    # if len(tcp.data) <= 0:
                    #     continue

                    # Check for specific application layer protocols
                    if tcp.dport == 80 or tcp.sport == 80:
                        http_count += 1
                    elif tcp.dport == 443 or tcp.sport == 443:
                        https_count += 1
                    elif tcp.dport == 22 or tcp.sport == 22:
                        SSH_count += 1
                    elif tcp.dport in (20, 21) or tcp.sport in (20, 21):
                        FTP_count += 1

            except Exception as e:
                print(f"An error occurred: {e}")

    # Print the counts
    print("HTTP: ", http_count)
    print("HTTPS: ", https_count)
    print("ICMP: ", ICMP_count)
    print("FTP: ", FTP_count)
    print("SSH: ", SSH_count)

# Replace with your pcap file path
parse_pcap("example_ping.pcap")
