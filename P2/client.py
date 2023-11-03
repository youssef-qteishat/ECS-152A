import socket
import time

#socket
#bind 
#listen
#accept

host = '127.0.0.1'
port = 5502
byte_size = b'x' * 100 * 1024 

def client():        
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client_socket:
        for i in range(0, len(byte_size)):
            client_socket.sendto(byte_size[i:i+1024], (host, port))

        measurement, addr = client_socket.recvfrom(1024)
        print(measurement.decode())
        client_socket.close()


if __name__ == '__main__':
    client()