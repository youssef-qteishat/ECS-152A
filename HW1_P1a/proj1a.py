import dpkt
import sys


# 1. Ping google.com for 20 packets.
def parse_pcap(pcap_file):

    app_layer_count = 0
    network_layer_count = 0
    transport_layer_count = 0

    # read the pcap file
    f = open(pcap_file, 'rb')
    pcap = dpkt.pcap.Reader(f)

    # iterate over packets
    for timestamp, data in pcap:

        # convert to link layer object
        eth = dpkt.ethernet.Ethernet(data)

        # do not proceed if there is no network layer data
        if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
            continue
        
        # extract network layer data
        ip = eth.data
        network_layer_count += 1

        # do not proce
        # ed if there is no transport layer data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # extract transport layer data
        tcp = ip.data
        transport_layer_count += 1

        # do not proceed if there is no application layer data
        # here we check length because we don't know protocol yet
        if not len(tcp.data) > 0:
            continue

        # extract application layer data
        ## if destination port is 80, it is a http request
        if tcp.dport == 80:
            try:
                http = dpkt.http.Request(tcp.data)
                print(http.headers)
            except: 
                pass
                
        ## if source port is 80, it is a http response
        elif tcp.sport == 80:
            try:
                http = dpkt.http.Response(tcp.data)
                print(http.headers)
            except:
                pass

        print(network_layer_count)
        print(transport_layer_count)

    if __name__ == '__main__':
        if len(sys.argv) < 2:
            print("No pcap file specified!")
        else:
            parse_pcap(sys.argv[1])

parse_pcap(HW1_P1a/google_ping2.pcap)

# 2. Visit https://example.com in your browser.
# 3. Visit http://httpforever.com in your browser
# 4. Access a FTP server (Type “ftp ftp.gnu.org” in your terminal)
# 5. ssh into a CSIF machine