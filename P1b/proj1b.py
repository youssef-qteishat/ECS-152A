import dpkt
import sys
import json

def extract_json_from_http(packet_data):
    try:
        # Parse the HTTP request or response
        http_request = dpkt.http.Request(packet_data)
        # You can also use dpkt.http.Response for HTTP responses

        # Check if there's a content-type header with application/json
        content_type = http_request.headers.get('content-type', '')
        if 'application/json' not in content_type:
            return None  # Not JSON data

        # Extract the JSON data from the HTTP body
        json_data = json.loads(http_request.body)
        return json_data

    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData) as e:
        return None  # Not a valid HTTP packet


def sherlock(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for timestamp, data in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(data)
                # Extracting the source MAC address and converting it to a readable format
                src_mac = ':'.join('%02x' % b for b in eth.src)
                dst_mac = ':'.join('%02x' % b for b in eth.dst)
                print("source: ", src_mac)
                print("destinaton: ", dst_mac)

                if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):

                    ip = eth.data
                    if isinstance(ip.data, dpkt.icmp.ICMP):
                        print("ICMP Type:", ip.data.type)
                        print("ICMP Code:", ip.data.code)
                        payload = bytes(ip.data.data)
                        print(payload.decode('utf-8'))


                    if isinstance(ip.data, dpkt.tcp.TCP):

                        if b"HTTP" in ip.data.data:

                            if b"HTTP" in ip.data.data:
                                http_payload = ip.data.data.decode('utf-8')
                                lines = http_payload.split('\n')
                                for line in lines:
                                    if 'secret' in line:
                                        print(line)
                        # tcp = ip.data
                        # json_data = extract_json_from_http(tcp.data)

                        # if json_data:
                        #     print(json_data)

            except Exception as e:
                print(f"An error occurred: {e}")

sherlock("ass1_3.pcap")
