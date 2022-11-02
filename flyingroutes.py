from argparse import ArgumentParser
from socket import gethostbyname, socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, SOCK_RAW, IPPROTO_IP, IPPROTO_ICMP, IPPROTO_UDP, SOL_IP, IP_TTL, error
from struct import pack
from threading import Thread
from queue import Queue
from os import getpid
from time import sleep
from platform import system

FLAG = 'FLYINGROUTES'

def icmp_checksum(data):
    '''
    Checksum calculator for ICMP header from https://gist.github.com/pyos/10980172
        
            Parameters:
                data (str): data to derive checksum from
            Returns:
                checksum (int): calculated checksum
    '''    
    x = sum(x << 8 if i % 2 else x for i, x in enumerate(data)) & 0xFFFFFFFF
    x = (x >> 16) + (x & 0xFFFF)
    x = (x >> 16) + (x & 0xFFFF)
    checksum = ~x & 0xFFFF

    return checksum


def send_icmp(n_hops, host_ip, queue):
    '''
    ICMP sender thread function
        
            Parameters:
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                queue (Queue): queue to communicate with receiver thread
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = queue.get() # Wait to receive GO from receiver thread
    if not start:
        return status

    try:
        tx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        tx_socket.settimeout(timeout)
    except Exception as e:
        print(f'Cannot create socket: {e}')
        queue.put(False)
        return status

    for ttl in range(1, n_hops+1):
        try:
            # Prepare ICMP packet
            # Header: Code (8) - Type (0) - Checksum (using checksum function) - ID (unique so take process ID) - Sequence (1)
            header = pack("bbHHh", 8, 0, 0, getpid() & 0xFFFF, 1)
            data = pack(str(len((FLAG+str(ttl))))+'s', (FLAG+str(ttl)).encode()) # Data is flag + TTL value (needed for receiver to map response to TTL)
            calc_checksum = icmp_checksum(header + data) # Checksum value for header packing
            header = pack("bbHHh", 8, 0, calc_checksum, getpid() & 0xFFFF, 1)
            b_calc_checksum = int.from_bytes(calc_checksum.to_bytes(2, 'little'), 'big') # Keep checksum value in reverse endianness
            tx_socket.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            for n in range(packets_to_repeat): # Send several packets per TTL value
                tx_socket.sendto(header + data, (host_ip, 0))
                queue.put((None, b_calc_checksum, ttl)) # Store checksum and TTL value in queue for the receiver thread
        except error as e:
            print(f'Error while setting TTL and sending data: {e}')
            return status

    status = True
    return status


def send_udp(timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue):
    '''
    UDP sender thread function
        
            Parameters:
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                dst_port (int): destination port
                packets_to_repeat (int): number of packets to send for each TTL value
                queue (Queue): queue to communicate with receiver thread
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = queue.get() # Wait to receive GO from reveiver thread
    if not start:
        return status
    
    src_port=1024 # Source port usage starts from 1024
    for ttl in range(1, n_hops+1):
        src_port += 1 # Source port selection per TTL value will allow the receive function to associate sent UDP packets to receive ICMP messages
        try:
            tx_socket = socket(AF_INET, SOCK_DGRAM)
            tx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            return status
        bound = False
        while not bound: # Set source port (try all from 1024 up to 65535)
            try:
                tx_socket.bind(('', src_port))
                bound = True
            except error as e:
                #print(f'Error while binding sending socket to source port {src_port}: {e}')
                #print(f'Trying next source port...')
                src_port += 1
            if src_port > 65535:
                print(f'Cannot find available source port to bind sending socket')
                tx_socket.close()
                return status
        try:
            tx_socket.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            for n in range(packets_to_repeat): # Send several packets per TTL value but change the destination port (for ECMP routing)
                tx_socket.sendto((FLAG+str(ttl)).encode(), (host_ip, dst_port+n))
                queue.put((None, src_port, ttl)) # Store source port and TTL value in queue for the receiver thread
        except error as e:
            print(f'Error while setting TTL and sending data: {e}')
            tx_socket.close()
            return status
    status = True
    tx_socket.close()
    return status


def send_tcp(n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue):
    '''
    TCP sender thread function
        
            Parameters:
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                dst_port (int): destination port
                packets_to_repeat (int): number of packets to send for each TTL value
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = sync_queue.get() # Wait to receive GO from reveiver thread
    if not start:
        return status

    sockets = []
    src_port=1024 # Source port usage starts from 1024

    for ttl in range(1, n_hops+1):
        src_ports = []
        for n in range(packets_to_repeat): # Send several packets per TTL value but change the destination port (for ECMP routing)
            src_port += 1 # Source port selection per packet to send will allow the receive function to associate sent TCP packets to receive ICMP messages
            tx_socket = socket(AF_INET, SOCK_STREAM) # One socket per destination port (per packet to send)
            bound = False
            while not bound: # Set source port (try all from 1024 up to 65535)
                try:
                    tx_socket.bind(('', src_port))
                    bound = True
                except error as e:
                    #print(f'Error while binding sending socket to source port {src_port}: {e}')
                    #print(f'Trying next source port...')
                    src_port += 1
                if src_port > 65535:
                    print(f'Cannot find available source port to bind sending socket')
                    sync_queue.put(False)
                    return status
            tx_socket.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            tx_socket.setblocking(False) # Set socket in non-blocking mode to allow fast sending of all the packets
            src_ports.append(src_port) # Store source port used in the list of source ports for the current TTL value
            sockets.append((tx_socket, src_ports, ttl)) # Store socket, source ports and TTL value to check connection status later on
            try:
                tx_socket.connect((host_ip, dst_port+n)) # Try TCP connection
            except error as e:
                pass
 
    sleep(1) # To allow TCP connections to be established (if target is reached by some sockets), still lower than TCP idle timeout

    for s, src_ports, ttl in sockets: # Test connection status for each socket by trying to send data
        try:
            s.send((FLAG+str(ttl)).encode()) # Try sending TTL value in data
            queue.put((True, src_ports, ttl)) # Store True to indicate that target was reached with source port and TTL value in queue for the receiver thread
        except Exception as e:
            queue.put((None, src_ports, ttl)) # Store source port and TTL value in queue for the receiver thread
            s.close()
        s.close()
    sync_queue.put(True) # Indicate to the receiver thread that receiver can continue with mapping of sent responses to sent packets
    status = True
    return status


def print_results(host_ttl_results):
    '''
    Printing function to standard outputfor TTL results per hop
        
            Parameters:
                host_ttl_results (list): host IP addresses per TTL value
            Returns:
                None
    '''  
    for (res_host, res_ttl) in host_ttl_results: 
        print(f'Hop {res_ttl}: {res_host}')


def map_received_icmp_to_sent_udp(host, n_hops, host_ip, recv_host_sport, reached, queue):
    '''
    Mapping function to associate sent UDP packets (source port and TTL value) to received ICMP packets (host IP address and inner UDP source port)
        
            Parameters:
                host (str): target hostname
                n_hops (int): number of hops tried by doing TTL increases
                host_ip (str): IP address of target host
                recv_host_sport (list): receive information from ICMP packets (host IP address, inner UDP source port)
                reached (bool): weither the target host was reached or not
                queue (Queue): queue to communicate with sender thread
            Returns:
                host_ttl_results (list): TTL values and associated host IP addresses
    ''' 
    host_ttl_results = []
    host_sport_ttl = []

    while not queue.empty(): # Get all sent information by the sender thread from the queue
        (new_host, new_sport, new_ttl) = queue.get() # new_host is None from queue
        no_resp = True
        for (rhost, sport) in recv_host_sport: # Parse ICMP responses
            if sport == new_sport: # Use source port information to get associated recv_host
                no_resp = False
                new_host = rhost
                if not host_sport_ttl: # If results list is empty, let's add the first result element
                    host_sport_ttl.append((new_host, new_sport, new_ttl))
                else:
                    duplicate = False
                    for (rhost, sport, ttl) in host_sport_ttl: # Parse the already stored results
                        if (new_sport == sport): # Check if duplicate is found based on the source port (as different host could be seen due to ECMP if -r option was passed)
                            duplicate = True
                            if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                host_sport_ttl.append((new_host, new_sport, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                            elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                host_sport_ttl.append((new_host+', '+rhost, new_sport, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                    if not duplicate: # If no duplicate, just add it to the results
                        host_sport_ttl.append((new_host, new_sport, new_ttl))
        if no_resp and not ('* * * * * * *', new_sport, new_ttl) in host_sport_ttl: # No response has been seen for this source port
            host_sport_ttl.append(('* * * * * * *', new_sport, new_ttl))
   
    # Find host TTL if reached
    reached_host_ttl = n_hops
    if reached:
        for (rhost, sport, ttl) in host_sport_ttl: 
            if host_ip == rhost:
                reached_host_ttl = ttl
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')     
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops') 
    
    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (rhost, sport, ttl) in host_sport_ttl:
        if ttl <= reached_host_ttl:
            host_ttl_results.append((rhost, ttl))
    
    return host_ttl_results 


def receive_udp(timeout, n_hops, host, host_ip, packets_to_repeat, queue):
    '''
    UDP receiver (of ICMP packets) thread function
        
            Parameters:
                timeout (int): socket timeout value
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                queue (Queue): queue to communicate with sender thread
            Returns:
                status (bool): return status (True: success, False: failure)
    ''' 
    status = False

    rx_socket = None

    if system() == 'Darwin':
        try:
            rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
            rx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            queue.put(False)
            return status
    else:
        try:
            rx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            rx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            queue.put(False)
            return status

    reached = False
    recv_data_addr = []
    timed_out = False
    queue.put(True) # Indicate to the sender thread that receiver thread is ready

    for n in range(n_hops*packets_to_repeat): # Receive ICMP responses
        if not timed_out:
            try:
                recv_data_addr.append(rx_socket.recvfrom(1024))
            except error as e:
                timed_out = True
                #print(f'Timeout reached while some responses are still pending')

    if not recv_data_addr:
        print(f'No responses received')
        return status

    recv_host_sport = []

    for data, addr in recv_data_addr: # Parse received ICMP packets
        resp_host = addr[0]
        # Decode IP and then ICMP headers
        ip_header = data.hex()
        ip_header_len = int(ip_header[1], 16) * 4 * 2 # IP header length is a multiple of 32-bit (4 bytes or 4 * 2 nibbles) increment
        icmp_header = ip_header[ip_header_len:]
        icmp_type = int(icmp_header[0:2], 16)
        icmp_code = int(icmp_header[2:4], 16)
        # Decode inner IP and then inner UDP headers
        inner_ip_header = icmp_header[16:]
        inner_ip_header_len = int(inner_ip_header[1], 16) * 4 * 2 # IP header length is a multiple of 32-bit (4 bytes or 4 * 2 nibbles) increment
        inner_udp = inner_ip_header[inner_ip_header_len:]
        inner_udp_len = int(inner_udp[8:12], 16) * 2
        inner_udp = inner_udp[:inner_udp_len]
        inner_udp_sport = int(inner_udp[0:4], 16)
        if icmp_type == 11 and icmp_code == 0: # ICMP Time-to-live exceeded in transit
            recv_host_sport.append((resp_host, inner_udp_sport))
        if icmp_type == 3 and icmp_code == 3 and resp_host == host_ip: # ICMP Destination unreachable Port unreachable
            recv_host_sport.append((resp_host, inner_udp_sport))
            reached = True

    host_ttl_results = map_received_icmp_to_sent_udp(host, n_hops, host_ip, recv_host_sport, reached, queue)
    print_results(host_ttl_results)

    status = True
    return status


def map_received_icmp_to_sent_tcp(host, n_hops, host_ip, recv_host_sport, queue):
    '''
    Mapping function to associate sent TCP packets (source port and TTL value) to received ICMP packets (host IP address and inner TCP source port)
        
            Parameters:
                host (str): target hostname
                n_hops (int): number of hops tried by doing TTL increases
                host_ip (str): IP address of target host
                recv_host_sport (list): receive information from ICMP packets (host IP address, inner TCP source port)
                reached (bool): weither the target host was reached or not
                queue (Queue): queue to communicate with sender thread
            Returns:
                host_ttl_results (list): TTL values and associated host IP addresses
    ''' 
    host_ttl_results = []
    host_sport_ttl = []

    reached = False
    while not queue.empty(): # Get all sent information by the sender thread from the queue
        (new_host, new_sports, new_ttl) = queue.get() # new_host is None from queue except when target was reached
        if new_host: # Target was reached in sender thread
            reached = True
            new_host = host_ip
            recv_host_sport.append((new_host, new_sports)) # Let's append this as a TCP response too
        no_resp = True
        for (rhost, sport) in recv_host_sport: # Parse ICMP / TCP responses
            if (sport in new_sports) or (sport == new_sports): # Use source port information to get associated recv_host
                no_resp = False
                new_host = rhost
                if not host_sport_ttl: # If results list is empty, let's add the first result element
                    host_sport_ttl.append((new_host, sport, new_ttl))
                else:
                    duplicate = False
                    for (rhost, sport, ttl) in host_sport_ttl: # Parse the already stored results
                        if (sport in new_sports) or (sport == new_sports): # Check if duplicate is found based on the source port (as different host could be seen due to ECMP if -r option was passed)
                            duplicate = True
                            if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                host_sport_ttl.append((new_host, new_sports, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                            elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                host_sport_ttl.append((new_host+', '+rhost, new_sports, new_ttl))
                                host_sport_ttl.remove((rhost, new_sports, ttl))
                    if not duplicate: # If no duplicate, just add it to the results
                        host_sport_ttl.append((new_host, new_sports, new_ttl))
        if no_resp and not ('* * * * * * *', new_sports, new_ttl) in host_sport_ttl: # No response has been seen for this source port
            host_sport_ttl.append(('* * * * * * *', new_sports, new_ttl))
   
    # Find host TTL if reached
    reached_host_ttl = n_hops
    if reached:
        for (rhost, sport, ttl) in host_sport_ttl: 
            if host_ip == rhost:
                reached_host_ttl = ttl
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')      
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops')   
    
    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (rhost, sport, ttl) in host_sport_ttl:
        if ttl <= reached_host_ttl:
            host_ttl_results.append((rhost, ttl))
    
    return host_ttl_results


def receive_tcp(timeout, n_hops, host, host_ip, packets_to_repeat, queue, sync_queue):
    '''
    TCP receiver (of ICMP packets) thread function
        
            Parameters:
                timeout (int): socket timeout value
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
            Returns:
                status (bool): return status (True: success, False: failure)
    ''' 
    status = False

    rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
    rx_socket.settimeout(timeout)

    reached = False
    recv_data_addr = []
    timed_out = False

    sync_queue.put(True) # Indicate to the sender thread that receiver thread is ready

    for n in range(n_hops*packets_to_repeat): # Receive ICMP responses
        if not timed_out:
            try:
                recv_data_addr.append(rx_socket.recvfrom(1024))
            except error as e:
                timed_out = True
                #print(f'Timeout reached while some responses are still pending')

    if not recv_data_addr:
        print(f'No responses received')
        return status

    recv_host_sport = []
    for data, addr in recv_data_addr: # Parse received ICMP packets
        resp_host = addr[0]
        # Decode IP and then ICMP headers
        ip_header = data.hex()
        ip_header_len = int(ip_header[1], 16) * 4 * 2 # IP header length is a multiple of 32-bit (4 bytes or 4 * 2 nibbles) increment
        icmp_header = ip_header[ip_header_len:]
        icmp_type = int(icmp_header[0:2], 16)
        icmp_code = int(icmp_header[2:4], 16)
        # Decode inner IP and then inner TCP headers
        inner_ip_header = icmp_header[16:]
        inner_ip_header_len = int(inner_ip_header[1], 16) * 4 * 2 # IP header length is a multiple of 32-bit (4 bytes or 4 * 2 nibbles) increment
        inner_tcp = inner_ip_header[inner_ip_header_len:]
        inner_tcp_len = int(inner_tcp[8:12], 16) * 2
        inner_tcp = inner_tcp[:inner_tcp_len]
        inner_tcp_sport = int(inner_tcp[0:4], 16)
        if icmp_type == 11 and icmp_code == 0: # ICMP Time-to-live exceeded in transit
            recv_host_sport.append((resp_host, inner_tcp_sport)) 

    start = sync_queue.get() # Wait GO from sender thread which needs to test TCP connections before going to parse send packets and received responses   
    if not start:
        return status
    
    host_ttl_results = map_received_icmp_to_sent_tcp(host, n_hops, host_ip, recv_host_sport, queue)
    print_results(host_ttl_results)

    status = True
    return status


def map_received_icmp_to_sent_icmp(host, n_hops, host_ip, recv_host_checksum_ttl, reached, queue):
    '''
    Mapping function to associate sent ICMP packets (checksum and TTL value) to received ICMP packets (host IP address and inner ICMP checksum or TTL value from inner sent data)
        
            Parameters:
                host (str): target hostname
                n_hops (int): number of hops tried by doing TTL increases
                host_ip (str): IP address of target host
                recv_host_checksum_ttl (list): receive information from ICMP packets (host IP address, inner ICMP checksum, TTL value from inner sent data)
                reached (bool): weither the target host was reached or not
                queue (Queue): queue to communicate with sender thread
            Returns:
                host_ttl_results (list): TTL values and associated host IP addresses
    ''' 
    host_ttl_results = []
    host_ttl = []

    while not queue.empty(): # Get all sent information by the sender thread from the queue
        (new_host, new_checksum, new_ttl) = queue.get() # new_host is None from queue
        no_resp = True
        for (rhost, checksum, ttl) in recv_host_checksum_ttl:  # Parse ICMP responses
            if new_ttl == ttl or new_checksum == checksum: # Use TTL or checksum information to get associated recv_host 
                no_resp = False
                new_host = rhost
                if not host_ttl: # If results list is empty, let's add the first result element
                    host_ttl.append((new_host, new_ttl))
                else:
                    duplicate = False
                    for (rhost, ttl) in host_ttl: # Parse the already stored results
                        if new_host in rhost: # Check if duplicate is found based on the host (as different host could be seen if -r option was passed) and host
                            duplicate = True
                            if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                host_ttl.append((new_host, new_ttl))
                                host_ttl.remove((rhost, ttl))
                            elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                host_ttl.append((new_host+', '+rhost, new_ttl))
                                host_ttl.remove((rhost, ttl))
                    if not duplicate: # If no duplicate, just add it to the results
                        host_ttl.append((new_host, new_ttl))
        if no_resp and not ('* * * * * * *', new_ttl) in host_ttl: # No response has been seen for this source port
            host_ttl.append(('* * * * * * *', new_ttl))
   
    # Find host TTL if reached
    reached_host_ttl = n_hops
    if reached:
        for (rhost, ttl) in host_ttl:
            if host_ip == rhost:
                reached_host_ttl = ttl
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')    
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops')   
    
    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (rhost, ttl) in host_ttl:
        if ttl <= reached_host_ttl:
            host_ttl_results.append((rhost, ttl))
    
    return host_ttl_results


def receive_icmp(n_hops, host, host_ip, packets_to_repeat, queue):
    '''
    ICMP receiver thread function
        
            Parameters:
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                queue (Queue): queue to communicate with sender thread
            Returns:
                status (bool): return status (True: success, False: failure)
    '''
    status = False

    rx_socket = None

    if system() == 'Darwin':
        try:
            rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
            rx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            queue.put(False)
            return status
    else:
        try:
            rx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            rx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            queue.put(False)
            return status

    reached = False
    recv_data_addr = []
    timed_out = False

    queue.put(True) # Indicate to the sender thread that receiver thread is ready

    for n in range(n_hops*packets_to_repeat): # Receive ICMP responses
        if not timed_out:
            try:
                recv_data_addr.append(rx_socket.recvfrom(1024))
            except error as e:
                timed_out = True
                #print(f'Timeout reached while some responses are still pending')

    if not recv_data_addr:
        print(f'No responses received')
        return status

    recv_host_ttl = []
    for data, addr in recv_data_addr: # Parse received ICMP packets
        resp_host = addr[0]
        # Decode IP and then ICMP headers
        ip_header = data.hex()
        ip_header_len = int(ip_header[1], 16) * 4 * 2 # IP header length is a multiple of 32-bit (4 bytes or 4 * 2 nibbles) increment
        icmp_header = ip_header[ip_header_len:]
        icmp_type = int(icmp_header[0:2], 16)
        icmp_code = int(icmp_header[2:4], 16)
        if icmp_type == 11 and icmp_code == 0: # ICMP Time-to-live exceeded in transit
            # Decode inner IP and then inner ICMP headers
            inner_ip_header = icmp_header[16:]
            inner_ip_header_len = int(inner_ip_header[1], 16) * 4 * 2 # Inner IP header length is a multiple of 32-bit (4 bytes or 4 * 2 nibbles) increment
            inner_icmp_header = inner_ip_header[inner_ip_header_len:]
            inner_icmp_checksum = int(inner_icmp_header[4:8], 16)
            recv_host_ttl.append((resp_host, inner_icmp_checksum, None)) # Store host and inner ICMP checksum
        if icmp_type == 0 and icmp_code == 0 and resp_host == host_ip: # ICMP Echo reply
            icmp_data = icmp_header[16:len(icmp_header)]
            ttl = int(bytes.fromhex(icmp_data).decode().split(FLAG)[1]) # Retrieve TTL from sent data
            recv_host_ttl.append((resp_host, None, ttl)) # Store host and TTL
            reached = True

    host_ttl_results = map_received_icmp_to_sent_icmp(host, n_hops, host_ip, recv_host_ttl, reached, queue)
    print_results(host_ttl_results)

    status = True
    return status


if __name__ == '__main__':
    
    # Argument parsing from command-line
    parser = ArgumentParser()

    parser.add_argument(
        'HOST',
        type = str,
        help = 'target host'
    )

    parser.add_argument(
        '--number_of_hops', '-n',
        type = int,
        action = 'store',
        default = 30,
        help = 'Max number of hops allowed to reach the target (default: 30)'
    )

    parser.add_argument(
        '--protocol', '-p',
        type = str,
        action = 'store',
        default = 'icmp',
        help = 'Protocol to use: ICMP, UDP or TCP (default: ICMP)'
    )

    parser.add_argument(
        '--dest_port', '-d',
        type = int,
        action = 'store',
        default = None,
        help = 'Port to use for UDP and TCP only (default: 33434), increased by 1 for each additional packets sent with the --repeat option'
    )

    parser.add_argument(
        '--timeout', '-t',
        type = int,
        action = 'store',
        default = 3,
        help = 'Timeout for responses (default: 3s for UDP, 5s for TCP)'
    )

    parser.add_argument(
        '--repeat', '-r',
        type = int,
        action = 'store',
        default = 3,
        help = 'Number of packets to repeat per TTL value increase using different destination ports (default: 3, max: 16)'
    )

    args = vars(parser.parse_args())

    host = args['HOST']
    try:
        host_ip = gethostbyname(host)
    except Exception as e:
        print(f'Cannot resolve target host {e}')
        exit()

    n_hops = int(args['number_of_hops'])
    if n_hops < 1 or n_hops > 255:
        print(f'Number of hops must be between 1 and 255')
        exit()

    protocol = args['protocol']
    if not (protocol == 'icmp' or protocol == 'udp' or protocol == 'tcp'):
        print(f'{protocol} is not a supported protocol')
        exit()

    dst_port = 33434
    if args['dest_port']:
        if protocol == 'icmp':
            print(f'Destination port is only valid for UDP or TCP protocols')
            exit()
        elif (args['dest_port'] < 1 or args['dest_port'] > 65535):
            print(f'Destination port must be between 1 and 65535')
            exit()
        else:
            dst_port = int(args['dest_port'])
    
    timeout = int(args['timeout'])
    if timeout <= 0:
        print(f'Timeout value must be positive')
        exit()

    packets_to_repeat = int(args['repeat'])
    if packets_to_repeat < 1 or packets_to_repeat > 16:
        print(f'Number of packet to send per TTL value increase must be between 1 and 16')
        exit()
    
    match protocol:
        case 'udp':
            print(f'flyingroutes to {host} ({host_ip}) with {n_hops} hops max ({packets_to_repeat} packets per hop) on UDP port {dst_port} with a timeout of {timeout}s')
            try:
                queue = Queue()
            except Exception as e:
                print(f'Cannot start queue for thread information exchanges: {e}')
            try:
                rx_thread = Thread(target=receive_udp, args=(timeout, n_hops, host, host_ip, packets_to_repeat, queue))
                tx_thread = Thread(target=send_udp, args=(timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue))
                rx_thread.start()
                tx_thread.start()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')
        case 'tcp':
            print(f'flyingroutes to {host} ({host_ip}) with {n_hops} hops max ({packets_to_repeat} packets per hop) on TCP port {dst_port} with a timeout of {timeout}s')
            try:
                queue = Queue()
                sync_queue = Queue()
            except Exception as e:
                print(f'Cannot start queues for thread information exchanges: {e}')
            try:
                rx_thread = Thread(target=receive_tcp, args=(timeout, n_hops, host, host_ip, packets_to_repeat, queue, sync_queue))
                tx_thread = Thread(target=send_tcp, args=(n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue))
                rx_thread.start()
                tx_thread.start()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')
        case _:
            print(f'flyingroutes to {host} ({host_ip}) with {n_hops} hops max ({packets_to_repeat} packets per hop) on ICMP with a timeout of {timeout}s')
            try:
                queue = Queue()
            except Exception as e:
                print(f'Cannot start queue for thread information exchanges: {e}')
            try:
                rx_thread = Thread(target=receive_icmp, args=(n_hops, host, host_ip, packets_to_repeat, queue))
                tx_thread = Thread(target=send_icmp, args=(n_hops, host_ip, queue))
                rx_thread.start()
                tx_thread.start()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')