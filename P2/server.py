import socket
import time

#socket
#bind 
#listen
#accept

host = '127.0.0.1'
port = 5502

def server():
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))

        received_bytes = 0
        max_data = 100 * 1024
        received_data = bytearray()
        start_time = time.time()
        while received_bytes < max_data:
            data, addr = server_socket.recvfrom(1024)
            received_bytes += len(data)
            received_data.extend(data)


        end_time = time.time()
        time_taken = end_time - start_time
        data = data.decode()
        msg = str(100*1024/time_taken).encode()
        server_socket.sendto(msg,addr)

        server_socket.close()

if __name__ == '__main__':
    server()


    
