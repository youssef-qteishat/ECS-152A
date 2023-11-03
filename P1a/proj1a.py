import dpkt
import sys
import datetime

# only list packets that are related to activity
def parse_pcap(pcap_file):

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    http_count = 0
    https_count = 0
    FTC_count = 0
    FTP_count = 0
    ICMP_count = 0
    ARP_count = 0
    SSH_count = 0

    # iterate over packets
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
            continue

        # extract network layer data
        ip = eth.data

        if isinstance(ip.data, dpkt.icmp.ICMP):
            ICMP_count += 1
            # icmp = ip.data

        #destination IP adress in IPv4 format
        src_ip = dpkt.utils.inet_to_str(ip.src)
        dst_ip = dpkt.utils.inet_to_str(ip.dst)

        print("Source IP: ", src_ip)
        print("Destination IP: ", dst_ip)
       
        # Dont procced if there is no transport layer data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        
        # extract transport layer data
        tcp = ip.data

        # do not proceed if there is no application layer data
        # here we check length because we don't know protocol yet
        if not len(tcp.data) > 0:
            continue

        # extract application layer data
        # HTTP, HTTPS, SSH, FTC, FTP, ICMP, 

        #########################################################################################################################################################

        # HTTP Request or HTTP Response
        # print(tcp.dport)
        # print(tcp.sport)
        if tcp.dport == 80 or tcp.sport == 80 or tcp.dport == 8080 or tcp.sport == 8080: 
             http_count += 1
        
        #https:
        if tcp.dport == 443 or tcp.sport == 443:
            https_count += 1
            
        #SSH:
        if tcp.dport == 22 or tcp.sport == 22:
            SSH_count += 1
        
        #FTP:
        if tcp.dport == 21 or tcp.dport == 20 or tcp.sport == 20 or tcp.sport == 21:
            FTP_count += 1

        #########################################################################################################################################################
        print ('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
        print("IPV4: ", dest_ip)
    print("HTTP: ", http_count)
    print("HTTPS: ", https_count)
    print("ICMP: ", ICMP_count)
    print("FTP: ", FTP_count)
    print("SSH: ", SSH_count)
            
# parse_pcap("google_ping (1).pcap")
# parse_pcap("example_ping.pcap")
# parse_pcap("http_forever.pcap")
# parse_pcap("FTP_wireshark.pcap")
parse_pcap("CSIF_wireshark.pcap")

# 2. Visit https://example.com in your browser.
# 3. Visit http://httpforever.com in your browser
# 4. Access a FTP server (Type “ftp ftp.gnu.org” in your terminal)
# 5. ssh into a CSIF machine