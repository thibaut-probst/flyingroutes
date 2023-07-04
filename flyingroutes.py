from argparse import ArgumentParser
from socket import gethostbyname, gethostbyaddr, socket, AF_INET, SOCK_DGRAM, SOCK_STREAM, SOCK_RAW, IPPROTO_IP, IPPROTO_ICMP, IPPROTO_UDP, SOL_IP, IP_TTL, error
from struct import pack
from threading import Thread
from queue import Queue
from os import getpid
from time import sleep, time
from platform import system
from rich.progress import Progress

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



def send_icmp(progress, sender_task, timeout, n_hops, host_ip, queue, sync_queue, stop_queue):
    '''
    ICMP sender thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                sender_task (Task): rich Task object to update
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                queue (Queue): queue to communicate with receiver thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with receiver thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = queue.get() # Wait to receive GO from receiver thread
    if not start:
        progress.remove_task(sender_task)
        sync_queue.put(True)
        return status

    progress.update(sender_task, visible=True)

    target_reached = False

    for ttl in range(1, n_hops+1):
        try:
            tx_socket = None
            if system() == 'Darwin':
                tx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
            else:
                tx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            tx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            progress.remove_task(sender_task)
            sync_queue.put(True)
            return status
        try:
            # Prepare ICMP packet
            # Header: Code (8) - Type (0) - Checksum (using checksum function) - ID (unique so take process ID) - Sequence (1)
            header = pack("bbHHh", 8, 0, 0, getpid() & 0xFFFF, 1)
            data = pack(str(len((FLAG+str(ttl))))+'s', (FLAG+str(ttl)).encode()) # Data is flag + TTL value (needed for receiver to map response to TTL)
            calc_checksum = icmp_checksum(header + data) # Checksum value for header packing
            header = pack("bbHHh", 8, 0, calc_checksum, getpid() & 0xFFFF, 1)
            b_calc_checksum = int.from_bytes(calc_checksum.to_bytes(2, 'little'), 'big') # Keep checksum value in reverse endianness
            if system() == 'Windows':
                tx_socket.setsockopt(IPPROTO_IP, IP_TTL, ttl) # Set TTL value
            else:
                tx_socket.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            for n in range(packets_to_repeat): # Send several packets per TTL value
                tx_socket.sendto(header + data, (host_ip, 0))
                send_time = time()
                queue.put((None, b_calc_checksum, ttl, send_time)) # Store checksum and TTL value in queue for the receiver thread
                progress.update(sender_task, advance=1)
                try:
                    target_reached = stop_queue.get(block=False)
                except:
                    pass
                if target_reached:
                    break
            tx_socket.close()
        except error as e:
            print(f'Error while setting TTL and sending data: {e}')
            tx_socket.close()
            progress.remove_task(sender_task)
            sync_queue.put(True)
            return status
        if target_reached:
            break

    progress.update(sender_task, completed=n_hops*packets_to_repeat)
    progress.remove_task(sender_task)

    sync_queue.put(True)

    status = True
    return status


def send_udp(progress, sender_task, timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue, stop_queue):
    '''
    UDP sender thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                sender_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                dst_port (int): destination port
                packets_to_repeat (int): number of packets to send for each TTL value
                queue (Queue): queue to communicate with receiver thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with receiver thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = queue.get() # Wait to receive GO from reveiver thread
    if not start:
        progress.remove_task(sender_task)
        return status

    progress.update(sender_task, visible=True)

    src_port = 1024 # Source port usage starts from 1024

    target_reached = False

    for ttl in range(1, n_hops+1):
        src_port += 1 # Source port selection per TTL value will allow the receive function to associate sent UDP packets to receive ICMP messages
        try:
            tx_socket = socket(AF_INET, SOCK_DGRAM)
            tx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            progress.remove_task(sender_task)
            sync_queue.put(True)
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
                progress.remove_task(sender_task)
                sync_queue.put(True)
                return status
        try:
            if system() == 'Windows':
                tx_socket.setsockopt(IPPROTO_IP, IP_TTL, ttl) # Set TTL value
            else:
                tx_socket.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            for n in range(packets_to_repeat): # Send several packets per TTL value but change the destination port (for ECMP routing)
                tx_socket.sendto((FLAG+str(ttl)).encode(), (host_ip, dst_port+n))
                send_time = time()
                queue.put((None, src_port, ttl, send_time)) # Store source port and TTL value in queue for the receiver thread
                progress.update(sender_task, advance=1)
                try:
                    target_reached = stop_queue.get(block=False)
                except:
                    pass
                if target_reached:
                    tx_socket.close()
                    break
            tx_socket.close()
        except error as e:
            print(f'Error while setting TTL and sending data: {e}')
            tx_socket.close()
            progress.remove_task(sender_task)
            sync_queue.put(True)
            return status
        if target_reached:
            break

    progress.remove_task(sender_task)
    sync_queue.put(True)

    status = True    
    return status


def send_tcp(progress, sender_task, timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue, stop_queue):
    '''
    TCP sender thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                sender_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                dst_port (int): destination port
                packets_to_repeat (int): number of packets to send for each TTL value
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with receiver thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = sync_queue.get() # Wait to receive GO from reveiver thread
    if not start:
        progress.remove_task(sender_task)
        sync_queue.put(True)
        return status

    progress.update(sender_task, visible=True)

    sockets = []
    src_port = 1024 # Source port usage starts from 1024

    target_reached = False

    for ttl in range(1, n_hops+1):
        src_ports = []
        for n in range(packets_to_repeat): # Send several packets per TTL value but change the destination port (for ECMP routing)
            src_port += 1 # Source port selection per packet to send will allow the receive function to associate sent TCP packets to receive ICMP messages
            try:    
                tx_socket = socket(AF_INET, SOCK_STREAM) # One socket per destination port (per packet to send)
            except Exception as e:
                print(f'Cannot create socket: {e}')
                progress.remove_task(sender_task)
                sync_queue.put(True)
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
                    progress.remove_task(sender_task)
                    sync_queue.put(True)
                    return status
            if system() == 'Windows':
                tx_socket.setsockopt(IPPROTO_IP, IP_TTL, ttl) # Set TTL value
            else:
                tx_socket.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            tx_socket.setblocking(False) # Set socket in non-blocking mode to allow fast sending of all the packets
            src_ports.append(src_port) # Store source port used in the list of source ports for the current TTL value
            try:
                tx_socket.connect((host_ip, dst_port+n)) # Try TCP connection
            except error as e:
                pass
            finally:
                send_time = time()
                sockets.append((tx_socket, src_ports, ttl, send_time)) # Store socket, source ports and TTL value to check connection status later on
            progress.update(sender_task, advance=1)
            try:
                target_reached = stop_queue.get(block=False)
            except:
                pass
            if target_reached:
                break
        if target_reached:
            break

    progress.update(sender_task, completed=n_hops*packets_to_repeat)
    progress.remove_task(sender_task)

    sleep(timeout) # To allow TCP connections to be established (if target is reached by some sockets), still lower than TCP idle timeout
    
    for s, src_ports, ttl, send_time in sockets: # Test connection status for each socket by trying to send data
        try:
            s.send((FLAG+str(ttl)).encode()) # Try sending TTL value in data
            queue.put((True, src_ports, ttl, send_time)) # Store True to indicate that target was reached with source port and TTL value in queue for the receiver thread
        except Exception as e:
            queue.put((None, src_ports, ttl, send_time)) # Store source port and TTL value in queue for the receiver thread
            s.close()
        s.close()
    
    sync_queue.put(True) # Indicate to the receiver thread that receiver can continue with mapping of sent responses to sent packets
    
    status = True
    return status


def send_all(progress, sender_task, timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue, stop_queue):
    '''
    UDP, ICMP & TCP sender thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                sender_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host_ip (str): IP address of target host
                dst_port (int): destination port
                packets_to_repeat (int): number of packets to send for each TTL value
                queue (Queue): queue to communicate with receiver thread
                sync_queue (Queue): queue to communicate with receiver thread
                stop_queue (Queue): queue to communicate with receiver thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    '''  
    status = False

    start = queue.get() # Wait to receive GO from reveiver thread
    if not start:
        progress.remove_task(sender_task)
        sync_queue.put(True)
        return status

    progress.update(sender_task, visible=True)

    tcp_sockets = []

    # Preparation of ICMP Socket
    try:
        tx_socket_icmp = None
        if system() == 'Darwin':
            tx_socket_icmp = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        else:
            tx_socket_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        tx_socket_icmp.settimeout(timeout)
    except Exception as e:
        print(f'Cannot create ICMP socket: {e}')
        progress.remove_task(sender_task)
        sync_queue.put(True)
        return status

    src_port = 1024 # Source port usage starts from 1024

    target_reached = False

    for ttl in range(1, n_hops+1):

        src_port += 1 # Source port selection per TTL value will allow the receive function to associate sent UDP packets to receive ICMP messages
        src_ports_tcp = []

        # Preparation of UDP Socket
        try:
            tx_socket_udp = socket(AF_INET, SOCK_DGRAM)
            tx_socket_udp.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create UDP socket: {e}')
            progress.remove_task(sender_task)
            sync_queue.put(True)
            return status
        # Binding of UDP socket
        udp_bound = False
        while not udp_bound: # Set source port (try all from 1024 up to 65535)
            try:
                tx_socket_udp.bind(('', src_port))
                udp_bound = True
            except error as e:
                #print(f'Error while binding sending socket to source port {src_port}: {e}')
                #print(f'Trying next source port...')
                src_port += 1
            if src_port > 65535:
                print(f'Cannot find available source port to bind UDP sending socket')
                tx_socket_udp.close()
                progress.remove_task(sender_task)
                sync_queue.put(True)
                return status
        
        # ICMP TTL and data preparation
        try:
            # Header: Code (8) - Type (0) - Checksum (using checksum function) - ID (unique so take process ID) - Sequence (1)
            header = pack("bbHHh", 8, 0, 0, getpid() & 0xFFFF, 1)
            data = pack(str(len((FLAG+str(ttl))))+'s', (FLAG+str(ttl)).encode()) # Data is flag + TTL value (needed for receiver to map response to TTL)
            calc_checksum = icmp_checksum(header + data) # Checksum value for header packing
            header = pack("bbHHh", 8, 0, calc_checksum, getpid() & 0xFFFF, 1)
            b_calc_checksum = int.from_bytes(calc_checksum.to_bytes(2, 'little'), 'big') # Keep checksum value in reverse endianness
            if system() == 'Windows':
                tx_socket_icmp.setsockopt(IPPROTO_IP, IP_TTL, ttl) # Set TTL value
            else:
                tx_socket_icmp.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
        except error as e:
            print(f'Error while setting TTL on ICMP socket: {e}')
            tx_socket_icmp.close()
            progress.remove_task(sender_task)
            sync_queue.put(True)
            return status
        
        # UDP TTL preparation
        try:
            if system() == 'Windows':
                tx_socket_udp.setsockopt(IPPROTO_IP, IP_TTL, ttl) # Set TTL value
            else:
                tx_socket_udp.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
        except error as e:
            print(f'Error while setting TTL on UDP socket: {e}')
            tx_socket_udp.close()
            progress.remove_task(sender_task)
            sync_queue.put(True)
            return status

        # Sending the packets
        for n in range(packets_to_repeat): # Send several packets per TTL value but change the destination port (for ECMP routing)
            # ICMP
            try:
                tx_socket_icmp.sendto(header + data, (host_ip, 0))
                send_time = time()
                queue.put(('icmp', None, b_calc_checksum, ttl, send_time)) # Store checksum and TTL value in queue for the receiver thread
            except error as e:
                print(f'Error while sending ICMP data, continuing with other protocols: {e}')
                tx_socket_icmp.close()
            # UDP
            try:
                tx_socket_udp.sendto((FLAG+str(ttl)).encode(), (host_ip, dst_port+n))
                send_time = time()
                queue.put(('udp', None, src_port, ttl, send_time)) # Store source port and TTL value in queue for the receiver thread
            except error as e:
                print(f'Error while sending UDP data, continuing with other protocols: {e}')
                tx_socket_udp.close()
            # TCP
            src_port += 1 # Source port selection per packet to send will allow the receive function to associate sent TCP packets to receive ICMP messages
            try:
                tx_socket_tcp = socket(AF_INET, SOCK_STREAM) # One socket per destination port (per packet to send)
            except Exception as e:
                print(f'Cannot create TCP socket: {e}')
                tx_socket_icmp.close()
                progress.remove_task(sender_task)
                sync_queue.put(True)
                return status
            bound = False
            while not bound: # Set source port (try all from 1024 up to 65535)
                try:
                    tx_socket_tcp.bind(('', src_port))
                    bound = True
                except error as e:
                    #print(f'Error while binding sending socket to source port {src_port}: {e}')
                    #print(f'Trying next source port...')
                    src_port += 1
                if src_port > 65535:
                    print(f'Cannot find available source port to bind sending socket')
                    tx_socket_tcp.close()
                    progress.remove_task(sender_task)
                    sync_queue.put(True)
                    return status
            if system() == 'Windows':
                tx_socket_tcp.setsockopt(IPPROTO_IP, IP_TTL, ttl) # Set TTL value
            else:
                tx_socket_tcp.setsockopt(SOL_IP, IP_TTL, ttl) # Set TTL value
            tx_socket_tcp.setblocking(False) # Set socket in non-blocking mode to allow fast sending of all the packets
            src_ports_tcp.append(src_port) # Store source port used in the list of source ports for the current TTL value
            try:
                tx_socket_tcp.connect((host_ip, dst_port+n)) # Try TCP connection
            except error as e:
                pass
            finally:
                send_time = time()
                tcp_sockets.append((tx_socket_tcp, src_ports_tcp, ttl, send_time)) # Store socket, source ports and TTL value to check connection status later on
            progress.update(sender_task, advance=1)
            
            try:
                target_reached = stop_queue.get(block=False)
            except:
                pass
            if target_reached:
                break
        if target_reached:
            break

    progress.remove_task(sender_task)

    sleep(timeout) # To allow TCP connections to be established (if target is reached by some sockets), still lower than TCP idle timeout
    
    for s, src_ports_tcp, ttl, send_time in tcp_sockets: # Test connection status for each socket by trying to send data
        try:
            s.send((FLAG+str(ttl)).encode()) # Try sending TTL value in data
            queue.put(('tcp', True, src_ports_tcp, ttl, send_time)) # Store True to indicate that target was reached with source port and TTL value in queue for the receiver thread
        except Exception as e:
            queue.put(('tcp', None, src_ports_tcp, ttl, send_time)) # Store source port and TTL value in queue for the receiver thread
            s.close()
        s.close()

    sync_queue.put(True)  # Indicate to the receiver thread that receiver can continue with mapping of sent responses to sent packets

    tx_socket_icmp.close()
    tx_socket_udp.close()

    status = True
    return status


def print_results(host_ttl_results, host_delta_time):
    '''
    Printing function to standard outputfor TTL results per hop
        
            Parameters:
                host_ttl_results (list or dict): host IP addresses per TTL value (and per protocol if dict)
                host_delta_time (dict): response time per host and protocol
            Returns:
                None
    '''
    if isinstance(host_ttl_results, list): # Single protocol (no protocol and list of tuples)
        for (res_host, res_ttl) in host_ttl_results:
            hop_space = f''
            if res_ttl < 10:
                hop_space = f' '
            host_fqdn = ''
            if ',' in res_host: # Several hosts for this TTL
                res_host_list = res_host.replace(' ', '').split(',')
                for host in res_host_list:
                    if res_host_list.index(host) == 0:
                        s = f'Hop {res_ttl}: {hop_space}'
                    else:
                        s = f'        '
                    host_fqdn = ''
                    try:
                        fqdn = ''
                        fqdn = gethostbyaddr(host)[0]
                        host_fqdn = f' ({fqdn})'
                    except:
                        pass
                    if host in host_delta_time.keys():
                        if host_delta_time[host] <= 0:
                            s += f'{host}{host_fqdn}'
                        else:
                            s += f'{host}{host_fqdn} - {round(host_delta_time[host]*1000,2)}ms'
                    else:
                        s += f'{host}{host_fqdn}'
                    print(f'{s}')
                    host_fqdn = ''
            elif res_host in host_delta_time.keys(): # One host for this TTL
                host_fqdn = ''
                try:
                    fqdn = ''
                    fqdn = gethostbyaddr(res_host)[0]
                    host_fqdn = f' ({fqdn})'
                except:
                    pass
                if host_delta_time[res_host] <= 0:
                    print(f'Hop {res_ttl}: {hop_space}{res_host}{host_fqdn}')
                else:
                    print(f'Hop {res_ttl}: {hop_space}{res_host}{host_fqdn} - {round(host_delta_time[res_host]*1000,2)}ms')
            else:
                print(f'Hop {res_ttl}: {hop_space}{res_host}{host_fqdn}')

    elif isinstance(host_ttl_results, dict): # All protocols (protocol and dict)
        for res_ttl in sorted(host_ttl_results.keys()):
            hop_space = f''
            if res_ttl < 10:
                hop_space = f' '
            ttl_str = ''
            for proto in host_ttl_results[res_ttl].keys():
                if proto == 'all': # All protocols failed to have a response
                    ttl_str += f'Hop {res_ttl}: {hop_space}{host_ttl_results[res_ttl][proto]} - ICMP, UDP and TCP'                
                else: # We parse the response per protocol
                    for res_host in host_ttl_results[res_ttl][proto]: # For each protocol, we parse the responses per host
                        if ',' in res_host: # Several hosts for the protocol
                            res_host_list = res_host.replace(' ', '').split(',')
                            for host in res_host_list:
                                if not f'Hop {res_ttl}: {hop_space}' in ttl_str:
                                    ttl_str += f'Hop {res_ttl}: {hop_space}'
                                elif not host in ttl_str:
                                    ttl_str += f'\n        '
                                host_fqdn = ''
                                try:
                                    fqdn = ''
                                    fqdn = gethostbyaddr(host)[0]
                                    host_fqdn = f' ({fqdn})'
                                except:
                                    pass
                                if (host in host_delta_time.keys()):
                                    if not host in ttl_str: # Create a new host line
                                        if host_delta_time[host][proto] <= 0:
                                            ttl_str += f'{host}{host_fqdn} - {proto.upper()}'                          
                                        else:
                                            ttl_str += f'{host}{host_fqdn} - {proto.upper()}: {round(host_delta_time[host][proto]*1000,2)}ms'
                                    else: # Add the protocol and response time info to the right existing host line
                                        lines = ttl_str.split('\n')
                                        ttl_str = ''
                                        for line in lines:
                                            if host in line:
                                                if host_delta_time[host][proto] <= 0:
                                                    line += f', {proto.upper()}'
                                                else:
                                                    line += f', {proto.upper()}: {round(host_delta_time[host][proto]*1000,2)}ms'
                                            ttl_str += '\n'+line
                                        ttl_str = ttl_str[1:] # Remove the first '\n' character
                                else:
                                    if not host in ttl_str: # Create a new host line                              
                                        ttl_str += f'{host}{host_fqdn} - {proto.upper()}'
                                    else: # Add the protocol and response time info to the right existing host line
                                        lines = ttl_str.split('\n')
                                        ttl_str = ''
                                        for line in lines:
                                            if host in line:
                                                ttl_str += f', {proto.upper()}'
                                            ttl_str += '\n'+line
                                        ttl_str = ttl_str[1:] # Remove the first '\n' character
                        else: # One host for the protocol
                            if not f'Hop {res_ttl}: {hop_space}' in ttl_str:
                                ttl_str += f'Hop {res_ttl}: {hop_space}'
                            elif not res_host in ttl_str:
                                ttl_str += f'\n        '
                            host_fqdn = ''
                            try:
                                fqdn = ''
                                fqdn = gethostbyaddr(res_host)[0]
                                host_fqdn = f' ({fqdn})'
                            except:
                                pass
                            if (res_host in host_delta_time.keys()):
                                if not res_host in ttl_str: # Create a new host line  
                                    if host_delta_time[res_host][proto] <= 0:  
                                        ttl_str += f'{res_host}{host_fqdn} - {proto.upper()}'                               
                                    else:
                                        ttl_str += f'{res_host}{host_fqdn} - {proto.upper()}: {round(host_delta_time[res_host][proto]*1000,2)}ms'
                                else: # Add the protocol and response time info to the right existing host line
                                    if host_delta_time[res_host][proto] <= 0: 
                                        ttl_str += f', {proto.upper()}'
                                    else:
                                        ttl_str += f', {proto.upper()}: {round(host_delta_time[res_host][proto]*1000,2)}ms'
                            else:
                                if not res_host in ttl_str: # Create a new host line 
                                    ttl_str += f'{res_host}{host_fqdn}, {proto.upper()}'
                                else: # Add the protocol and response time info to the right existing host line
                                    ttl_str += f', {proto.upper()}'
            print(f'{ttl_str}')


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
    host_delta_time = {}

    while not queue.empty(): # Get all sent information by the sender thread from the queue
        (new_host, new_sport, new_ttl, send_time) = queue.get() # new_host is None from queue
        no_resp = True
        for (rhost, sport, receive_time) in recv_host_sport: # Parse ICMP responses
            if sport == new_sport: # Use source port information to get associated recv_host
                no_resp = False
                new_host = rhost
                if not host_sport_ttl: # If results list is empty, let's add the first result element
                    host_sport_ttl.append((new_host, new_sport, new_ttl))
                    host_delta_time[new_host] = receive_time-send_time
                else:
                    duplicate = False
                    for (rhost, sport, ttl) in host_sport_ttl: # Parse the already stored results
                        if (new_sport == sport): # Check if duplicate is found based on the source port (as different host could be seen due to ECMP if -r option was passed)
                            duplicate = True
                            if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                host_sport_ttl.append((new_host, new_sport, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                                host_delta_time[new_host] = receive_time-send_time
                            elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                host_sport_ttl.append((new_host+', '+rhost, new_sport, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                                host_delta_time[new_host] = receive_time-send_time
                    if not duplicate: # If no duplicate, just add it to the results
                        host_sport_ttl.append((new_host, new_sport, new_ttl))
                        host_delta_time[new_host] = receive_time-send_time
        if no_resp and not ('* * * * * * * *', new_sport, new_ttl) in host_sport_ttl: # No response has been seen for this source port
            host_sport_ttl.append(('* * * * * * * *', new_sport, new_ttl))
   
    # Find host TTL if reached
    reached_host_ttl = n_hops
    if reached:
        for (rhost, sport, ttl) in host_sport_ttl:
            if host_ip in rhost:
                reached_host_ttl = ttl
                host_sport_ttl[host_sport_ttl.index((rhost, sport, ttl))] = (host_ip, sport, ttl)
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')     
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops') 
    
    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (rhost, sport, ttl) in host_sport_ttl:
        if ttl <= reached_host_ttl:
            host_ttl_results.append((rhost, ttl))

    # Add hops with no answers
    for n in range(1, n_hops+1):
        found = False
        for (rhost, sport, ttl) in host_sport_ttl:
            if n == ttl:
                found = True
        if not found and (n <= reached_host_ttl):
            host_ttl_results.append(('* * * * * * * *', n))
    
    return sorted(host_ttl_results, key=lambda a: a[1]), host_delta_time


def receive_udp(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, queue, sync_queue, stop_queue):
    '''
    UDP receiver (of ICMP packets) thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                receiver_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with sender thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    ''' 
    status = False

    system_platform = system()

    try:
        rx_socket = None
        if system_platform == 'Darwin':
            rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        else:
            rx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        rx_socket.settimeout(timeout)
    except Exception as e:
        print(f'Cannot create socket: {e}')
        queue.put(False)
        progress.remove_task(receiver_task)
        return status

    if system_platform == 'Windows':
        rx_socket.bind(('', 0))

    reached = False
    recv_data_addr = []
    timed_out = False

    progress.update(receiver_task, visible=True)

    sender_done = False
    timed_out = False

    queue.put(True) # Indicate to the sender thread that receiver thread is ready

    while True:
        timed_out = False
        try:
            data, addr = rx_socket.recvfrom(1024)
            recv_data_addr.append((data, addr, time()))
            progress.update(receiver_task, advance=1)
        except error as e:
            timed_out = True
            #print(f'Timeout reached while some responses are still pending')
            try:
                sender_done = sync_queue.get(block=False)
            except:
                pass
        if sender_done and timed_out:
            break

    progress.update(receiver_task, completed=n_hops*packets_to_repeat)

    if not recv_data_addr:
        print(f'No responses received')
        progress.remove_task(receiver_task)
        return status

    recv_host_sport = []

    for data, addr, receive_time in recv_data_addr: # Parse received ICMP packets
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
            recv_host_sport.append((resp_host, inner_udp_sport, receive_time))
        if icmp_type == 3 and icmp_code == 3 and resp_host == host_ip: # ICMP Destination unreachable Port unreachable
            recv_host_sport.append((resp_host, inner_udp_sport, receive_time))
            reached = True

    host_ttl_results, host_delta_time = map_received_icmp_to_sent_udp(host, n_hops, host_ip, recv_host_sport, reached, queue)
    
    progress.remove_task(receiver_task)
    
    print_results(host_ttl_results, host_delta_time)

    status = True
    return status


def map_received_icmp_to_sent_tcp(host, n_hops, host_ip, recv_host_sport, queue, dst_port):
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
    host_delta_time = {}

    reached = False
    while not queue.empty(): # Get all sent information by the sender thread from the queue
        (new_host, new_sports, new_ttl, send_time) = queue.get() # new_host is None from queue except when target was reached
        if new_host: # Target was reached in sender thread
            reached = True
            new_host = host_ip
            recv_host_sport.append((new_host, new_sports, new_ttl)) # Let's append this as a TCP response too
        no_resp = True
        for (rhost, sport, receive_time) in recv_host_sport: # Parse ICMP / TCP responses
            if (sport in new_sports) or (sport == new_sports): # Use source port information to get associated recv_host
                no_resp = False
                new_host = rhost
                if not host_sport_ttl: # If results list is empty, let's add the first result element
                    host_sport_ttl.append((new_host, sport, new_ttl))
                    host_delta_time[new_host] = receive_time-send_time
                else:
                    duplicate = False
                    for (rhost, sport, ttl) in host_sport_ttl: # Parse the already stored results
                        if (sport in new_sports) or (sport == new_sports): # Check if duplicate is found based on the source port (as different host could be seen due to ECMP if -r option was passed)
                            duplicate = True
                            if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                host_sport_ttl.append((new_host, new_sports, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                                host_delta_time[new_host] = receive_time-send_time
                            elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                host_sport_ttl.append((new_host+', '+rhost, new_sports, new_ttl))
                                host_sport_ttl.remove((rhost, sport, ttl))
                                host_delta_time[new_host] = receive_time-send_time
                    if not duplicate: # If no duplicate, just add it to the results
                        host_sport_ttl.append((new_host, new_sports, new_ttl))
                        host_delta_time[new_host] = receive_time-send_time
        if no_resp and not ('* * * * * * * *', new_sports, new_ttl) in host_sport_ttl: # No response has been seen for this source port
            host_sport_ttl.append(('* * * * * * * *', new_sports, new_ttl))
   
    # Find host TTL if reached
    reached_host_ttl = n_hops
    if reached:
        for (rhost, sport, ttl) in host_sport_ttl: 
            if host_ip in rhost:
                reached_host_ttl = ttl
                host_sport_ttl[host_sport_ttl.index((rhost, sport, ttl))] = (host_ip, sport, ttl)
                # Try adding delta time for target by performing another TCP connection (as so far the response time was measure based on ICMP answers)
                try:
                    tx_socket = socket(AF_INET, SOCK_STREAM)
                    start = time()
                    tx_socket.connect((host_ip, dst_port))
                    host_delta_time[host_ip] = time() - start
                except:
                    pass
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')      
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops')   

    # Add hops with no answers
    for n in range(1, n_hops+1):
        found = False
        for (rhost, sport, ttl) in host_sport_ttl:
            if n == ttl:
                found = True
        if not found and (n <= reached_host_ttl):
            host_ttl_results.append(('* * * * * * * *', n))

    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (rhost, sport, ttl) in host_sport_ttl:
        if ttl <= reached_host_ttl:
            host_ttl_results.append((rhost, ttl))

    return sorted(host_ttl_results, key=lambda a: a[1]), host_delta_time


def receive_tcp(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, dst_port, queue, sync_queue, stop_queue):
    '''
    TCP receiver (of ICMP packets) thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                receiver_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                dest_port (int): destination port
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with sender thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    ''' 
    status = False

    system_platform = system()

    try:
        rx_socket = None
        if system_platform == 'Darwin':
            rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        else:
            rx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        rx_socket.settimeout(timeout)
    except Exception as e:
        print(f'Cannot create socket: {e}')
        queue.put(False)
        progress.remove_task(receiver_task)
        return status

    if system_platform == 'Windows':
        rx_socket.bind(('', 0))

    reached = False
    recv_data_addr = []

    progress.update(receiver_task, visible=True)

    sender_done = False
    timed_out = False

    sync_queue.put(True) # Indicate to the sender thread that receiver thread is ready

    while True:
        timed_out = False
        try:
            data, addr = rx_socket.recvfrom(1024)
            recv_data_addr.append((data, addr, time()))
            progress.update(receiver_task, advance=1)
        except error as e:
            timed_out = True
            #print(f'Timeout reached while some responses are still pending')
            try:
                sender_done = sync_queue.get(block=False)
            except:
                pass
        if sender_done and timed_out:
            break

    progress.update(receiver_task, completed=n_hops*packets_to_repeat)

    if not recv_data_addr:
        print(f'No responses received')
        progress.remove_task(receiver_task)
        return status

    recv_host_sport = []
    for data, addr, receive_time in recv_data_addr: # Parse received ICMP packets
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
            recv_host_sport.append((resp_host, inner_tcp_sport, receive_time))
        if icmp_type == 3 and icmp_code == 3 and resp_host == host_ip: # ICMP Destination unreachable Port unreachable
            recv_host_sport.append((resp_host, inner_tcp_sport, receive_time))
            reached = True
    
    host_ttl_results, host_delta_time = map_received_icmp_to_sent_tcp(host, n_hops, host_ip, recv_host_sport, queue, dst_port)
    
    progress.remove_task(receiver_task)
    
    print_results(host_ttl_results, host_delta_time)

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
    host_delta_time = {}            

    while not queue.empty(): # Get all sent information by the sender thread from the queue
        (new_host, new_checksum, new_ttl, send_time) = queue.get() # new_host is None from queue
        no_resp = True
        for (rhost, checksum, ttl, receive_time) in recv_host_checksum_ttl:  # Parse ICMP responses
            if (new_ttl == ttl) or (new_checksum == checksum): # Use TTL or checksum information to get associated recv_host 
                no_resp = False
                new_host = rhost
                if not host_ttl: # If results list is empty, let's add the first result element
                    host_ttl.append((new_host, new_ttl))
                    host_delta_time[new_host] = receive_time-send_time
                else:
                    duplicate = False
                    for (rhost, ttl) in host_ttl: # Parse the already stored results
                        if new_host in rhost: # Check if duplicate is found based on the host (as different host could be seen if -r option was passed) and host
                            duplicate = True
                            if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                host_ttl.append((new_host, new_ttl))
                                host_ttl.remove((rhost, ttl))
                                host_delta_time[new_host] = receive_time-send_time
                            elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                host_ttl.append((new_host+', '+rhost, new_ttl,))
                                host_ttl.remove((rhost, ttl))
                                host_delta_time[new_host] = receive_time-send_time
                    if not duplicate: # If no duplicate, just add it to the results
                        host_ttl.append((new_host, new_ttl))
                        host_delta_time[new_host] = receive_time-send_time
        if no_resp and not ('* * * * * * * *', new_ttl) in host_ttl: # No response has been seen for this source port
            host_ttl.append(('* * * * * * * *', new_ttl))
   
    # Find host TTL if reached
    reached_host_ttl = n_hops
    if reached:
        for (rhost, ttl) in host_ttl:
            if host_ip in rhost:
                reached_host_ttl = ttl
                host_ttl[host_ttl.index((rhost, ttl))] = (host_ip, ttl)
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')    
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops')   

    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (rhost, ttl) in host_ttl:
        if ttl <= reached_host_ttl:
            host_ttl_results.append((rhost, ttl))

    # Add hops with no answers
    for n in range(1, n_hops+1):
        found = False
        for (rhost, ttl) in host_ttl:
            if n == ttl:
                found = True
        if not found and (n <= reached_host_ttl):
            host_ttl_results.append(('* * * * * * * *', n))

    return sorted(host_ttl_results, key=lambda a: a[1]), host_delta_time


def receive_icmp(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, queue, sync_queue, stop_queue):
    '''
    ICMP receiver thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                receiver_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with sender thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    '''
    status = False

    rx_socket = None

    system_platform = system()

    if system_platform == 'Darwin':
        try:
            rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
            rx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            queue.put(False)
            progress.remove_task(receiver_task)
            return status
    else:
        try:
            rx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            rx_socket.settimeout(timeout)
        except Exception as e:
            print(f'Cannot create socket: {e}')
            queue.put(False)
            progress.remove_task(receiver_task)
            return status

    if system_platform == 'Windows':
        rx_socket.bind(('', 0))

    reached = False
    recv_data_addr = []

    progress.update(receiver_task, visible=True)

    sender_done = False

    queue.put(True) # Indicate to the sender thread that receiver thread is ready
    
    while True:
        try:
            data, addr = rx_socket.recvfrom(1024)
            if addr[0] == host_ip:
                stop_queue.put(True)
            recv_data_addr.append((data, addr, time()))
            progress.update(receiver_task, advance=1)
        except error as e:
            #print(f'Timeout reached while some responses are still pending')
            try:
                sender_done = sync_queue.get(block=False)
            except:
                pass
            if sender_done:
                break

    progress.update(receiver_task, completed=n_hops*packets_to_repeat)

    if not recv_data_addr:
        print(f'No responses received')
        progress.remove_task(receiver_task)
        return status

    recv_host_ttl = []
    for data, addr, receive_time in recv_data_addr: # Parse received ICMP packets
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
            recv_host_ttl.append((resp_host, inner_icmp_checksum, None, receive_time)) # Store host and inner ICMP checksum
        if icmp_type == 0 and icmp_code == 0 and resp_host == host_ip: # ICMP Echo reply
            icmp_data = icmp_header[16:len(icmp_header)]
            ttl = int(bytes.fromhex(icmp_data).decode().split(FLAG)[1]) # Retrieve TTL from sent data
            recv_host_ttl.append((resp_host, None, ttl, receive_time)) # Store host and TTL
            reached = True

    host_ttl_results, host_delta_time = map_received_icmp_to_sent_icmp(host, n_hops, host_ip, recv_host_ttl, reached, queue)
    
    progress.remove_task(receiver_task)

    print_results(host_ttl_results, host_delta_time)

    status = True
    return status


def map_received_icmp_to_sent_all(timeout, host, n_hops, host_ip, recv_host_sport_udp, recv_host_sport_tcp, recv_host_checksum_ttl, reached, queue):
    '''
    Mapping function to associate sent UDP packets (source port and TTL value) to received ICMP packets (host IP address and inner UDP source port)
        
            Parameters:
                timeout (int): socket timeout (in seconds)
                host (str): target hostname
                n_hops (int): number of hops tried by doing TTL increases
                host_ip (str): IP address of target host
                recv_host_sport_udp (list): receive information from ICMP packets (host IP address, inner UDP source port)
                recv_host_sport_tcp (list): receive information from ICMP packets (host IP address, inner TCP source port)
                recv_host_checksum_ttl (list): receive information from ICMP packets (host IP address, inner ICMP checksum, TTL value from inner sent data)
                reached (bool): weither the target host was reached or not
                queue (Queue): queue to communicate with sender thread
            Returns:
                host_ttl_results (list): TTL values and associated host IP addresses
    ''' 
    host_ttl_results = {}
    host_sport_ttl = []
    host_ttl = []
    host_delta_time = {}

    no_resp_by_ttl = {}
    for t in range(1, n_hops+1):
        no_resp_by_ttl[t] = {}
        no_resp_by_ttl[t]['icmp'] = True
        no_resp_by_ttl[t]['udp'] = True
        no_resp_by_ttl[t]['tcp'] = True

    while not queue.empty(): # Get all sent information by the sender thread from the queue

        (proto, new_host, new_sport_or_checksum, new_ttl, send_time) = queue.get() # new_host is None from queue

        if proto == 'udp':
            for (rhost, sport, receive_time) in recv_host_sport_udp: # Parse ICMP responses
                if sport == new_sport_or_checksum: # Use source port information to get associated recv_host
                    no_resp_by_ttl[new_ttl][proto] = False
                    new_host = rhost
                    if not host_sport_ttl: # If results list is empty, let's add the first result element
                        host_sport_ttl.append(('udp', new_host, new_sport_or_checksum, new_ttl))
                        if not new_host in host_delta_time.keys():
                            host_delta_time[new_host] = {}
                        host_delta_time[new_host]['udp'] = receive_time-send_time
                    else:
                        duplicate = False
                        for (proto, rhost, sport, ttl) in host_sport_ttl: # Parse the already stored results
                            if (proto == 'udp') and (sport == new_sport_or_checksum): # Check if duplicate is found based on the source port (as different host could be seen due to ECMP if -r option was passed)
                                duplicate = True
                                if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                    host_sport_ttl.append(('udp', new_host, new_sport_or_checksum, new_ttl))
                                    host_sport_ttl.remove(('udp', rhost, sport, ttl))
                                    if not new_host in host_delta_time.keys():
                                        host_delta_time[new_host] = {}
                                    host_delta_time[new_host]['udp'] = receive_time-send_time
                                elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                    host_sport_ttl.append(('udp', new_host+', '+rhost, new_sport_or_checksum, new_ttl))
                                    host_sport_ttl.remove(('udp', rhost, sport, ttl))
                                    if not new_host in host_delta_time.keys():
                                        host_delta_time[new_host] = {}
                                    host_delta_time[new_host]['udp'] = receive_time-send_time
                        if not duplicate: # If no duplicate, just add it to the results
                            host_sport_ttl.append(('udp', new_host, new_sport_or_checksum, new_ttl))
                            if not new_host in host_delta_time.keys():
                                host_delta_time[new_host] = {}
                            host_delta_time[new_host]['udp'] = receive_time-send_time

        elif proto == 'icmp':
            for (rhost, checksum, ttl, receive_time) in recv_host_checksum_ttl:  # Parse ICMP responses
                if (new_ttl == ttl) or (new_sport_or_checksum == checksum): # Use TTL or checksum information to get associated recv_host 
                    no_resp_by_ttl[new_ttl][proto] = False
                    new_host = rhost
                    if not host_ttl: # If results list is empty, let's add the first result element
                        host_ttl.append(('icmp', new_host, new_ttl))
                        if not new_host in host_delta_time.keys():
                            host_delta_time[new_host] = {}
                        host_delta_time[new_host]['icmp'] = receive_time-send_time
                    else:
                        duplicate = False
                        for (proto, rhost, ttl) in host_ttl: # Parse the already stored results
                            if (proto == 'icmp') and (new_host in rhost): # Check if duplicate is found based on the host (as different host could be seen if -r option was passed) and host
                                duplicate = True
                                if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                    host_ttl.append(('icmp', new_host, new_ttl))
                                    host_ttl.remove(('icmp', rhost, ttl))
                                    if not new_host in host_delta_time.keys():
                                        host_delta_time[new_host] = {}
                                    host_delta_time[new_host]['icmp'] = receive_time-send_time
                                elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                    host_ttl.append(('icmp', new_host+', '+rhost, new_ttl))
                                    host_ttl.remove(('icmp', rhost, ttl))
                                    if not new_host in host_delta_time.keys():
                                        host_delta_time[new_host] = {}
                                    host_delta_time[new_host]['icmp'] = receive_time-send_time
                        if not duplicate: # If no duplicate, just add it to the results
                            host_ttl.append(('icmp', new_host, new_ttl))
                            if not new_host in host_delta_time.keys():
                                host_delta_time[new_host] = {}
                            host_delta_time[new_host]['icmp'] = receive_time-send_time

        elif proto == 'tcp':
            if new_host: # Target was reached in sender thread (new_host was set to True in this case)
                reached = True
                new_host = host_ip
                recv_host_sport_tcp.append((new_host, new_sport_or_checksum, 0)) # Let's append this as a TCP response too

            for (rhost, sport, receive_time) in recv_host_sport_tcp: # Parse ICMP / TCP responses

                if (sport in new_sport_or_checksum) or (sport == new_sport_or_checksum): # Use source port information to get associated recv_host
                    no_resp_by_ttl[new_ttl][proto] = False
                    new_host = rhost
                    if not host_sport_ttl: # If results list is empty, let's add the first result element
                        host_sport_ttl.append(('tcp', new_host, sport, new_ttl))
                        if not new_host in host_delta_time.keys():
                            host_delta_time[new_host] = {}
                        host_delta_time[new_host]['tcp'] = receive_time-send_time
                    else:
                        duplicate = False
                        for (proto, rhost, sport, ttl) in host_sport_ttl: # Parse the already stored results
                            if (proto == 'tcp') and ((sport in new_sport_or_checksum) or (sport == new_sport_or_checksum)): # Check if duplicate is found based on the source port (as different host could be seen due to ECMP if -r option was passed)
                                duplicate = True
                                if (new_host in rhost) and new_ttl < ttl:  # If same hosts (means we went above the number of hops), compare associated TTLs and replace if TTL is lower
                                    host_sport_ttl.append(('tcp', new_host, new_sport_or_checksum, new_ttl))
                                    host_sport_ttl.remove(('tcp', rhost, sport, ttl))
                                    if not new_host in host_delta_time.keys():
                                        host_delta_time[new_host] = {}
                                    host_delta_time[new_host]['tcp'] = receive_time-send_time
                                elif (not new_host in rhost) and new_ttl == ttl: # If different hosts and same TTL (means we got different hosts for same TTL), replace entry with one with both hosts
                                    host_sport_ttl.append(('tcp', new_host+', '+rhost, new_sport_or_checksum, new_ttl))
                                    host_sport_ttl.remove(('tcp', rhost, sport, ttl))
                                    if not new_host in host_delta_time.keys():
                                        host_delta_time[new_host] = {}
                                    host_delta_time[new_host]['tcp'] = receive_time-send_time
                        if not duplicate: # If no duplicate, just add it to the results
                            host_sport_ttl.append(('tcp', new_host, new_sport_or_checksum, new_ttl))
                            if not new_host in host_delta_time.keys():
                                host_delta_time[new_host] = {}
                            host_delta_time[new_host]['tcp'] = receive_time-send_time

    for ttl in no_resp_by_ttl.keys():
        if all(no_resp for no_resp in no_resp_by_ttl[ttl].values()): # No response has been seen for this TTL
            if not (('all', '* * * * * * * *', None, ttl) in host_sport_ttl): 
                host_sport_ttl.append(('all', '* * * * * * * *', None, ttl))
            if not (('all', '* * * * * * * *', ttl) in host_ttl):
                host_ttl.append(('all', '* * * * * * * *', ttl))
   

    # Find host TTL if reached
    reached_host_ttl = n_hops

    if reached:
        for (proto, rhost, ttl) in host_ttl:
            if host_ip in rhost:
                reached_host_ttl = ttl
                host_ttl[host_ttl.index((proto, rhost, ttl))] = (proto, host_ip, ttl)
                break
        for (proto, rhost, sport, ttl) in host_sport_ttl:
            if host_ip in rhost:
                reached_host_ttl = ttl
                host_sport_ttl[host_sport_ttl.index((proto, rhost, sport, ttl))] = (proto, host_ip, sport, ttl)
                try:
                    tx_socket = socket(AF_INET, SOCK_STREAM)
                    tx_socket.settimeout(timeout)
                    start = time()
                    tx_socket.connect((host_ip, dst_port))
                    host_delta_time[host_ip]['tcp'] = time() - start
                    tx_socket.close()
                except:
                    tx_socket.close()
                break
        print(f'{host} ({host_ip}) reached in {reached_host_ttl} hops')  
    else:
        print(f'{host} ({host_ip}) not reached in {reached_host_ttl} hops')   

    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (proto, rhost, ttl) in host_ttl:
        if ttl <= reached_host_ttl:
            if not ttl in host_ttl_results.keys():
                host_ttl_results[ttl] = {}
            if not proto in host_ttl_results[ttl].keys():
                host_ttl_results[ttl][proto] = []
            if rhost == '* * * * * * * *':
                host_ttl_results[ttl][proto] = rhost
            else:
                host_ttl_results[ttl][proto].append(rhost)
    
    # Only keep results with TTL below host TTL (discard upper TTL values)
    for (proto, rhost, sport, ttl) in host_sport_ttl:
        if ttl <= reached_host_ttl:
            if not ttl in host_ttl_results.keys():
                host_ttl_results[ttl] = {}
            if not proto in host_ttl_results[ttl].keys():
                host_ttl_results[ttl][proto] = []
            if rhost == '* * * * * * * *':
                host_ttl_results[ttl][proto] = rhost
            else:
                host_ttl_results[ttl][proto].append(rhost)
    
    # Add hops with no answers
    for n in range(1, n_hops+1):
        found = False
        for (proto, rhost, ttl) in host_ttl:
            if n == ttl:
                found = True
        for (proto, rhost, sport, ttl) in host_sport_ttl:
            if n == ttl:
                found = True
        if not found and (n <= reached_host_ttl):
            if not n in host_ttl_results.keys():
                host_ttl_results[n] = {}
            if not 'all' in host_ttl_results[n].keys():
                host_ttl_results[n]['all'] = []
            host_ttl_results[n]['all'] = '* * * * * * * *'

    return host_ttl_results, host_delta_time


def receive_all(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, dst_port, queue, sync_queue, stop_queue):
    '''
    UDP, ICMP & TCP receiver (of ICMP packets) thread function
        
            Parameters:
                progress (Progress): rich Progress object to manage tasks
                receiver_task (Task): rich Task object to update
                timeout (float): socket timeout (in seconds)
                n_hops (int): number of hops to try by doing TTL increases
                host (str): target hostname
                host_ip (str): IP address of target host
                packets_to_repeat (int): number of packets to receive for each TTL value
                dest_port (int): destination port
                queue (Queue): queue to communicate with sender thread
                sync_queue (Queue): queue to communicate with sender thread
                stop_queue (Queue): queue to communicate with sender thread to know if target is reached
            Returns:
                status (bool): return status (True: success, False: failure)
    ''' 
    status = False

    system_platform = system()

    try:
        rx_socket = None
        if system_platform == 'Darwin':
            rx_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        else:
            rx_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        rx_socket.settimeout(timeout)
    except Exception as e:
        print(f'Cannot create socket: {e}')
        queue.put(False)
        progress.remove_task(receiver_task)
        return status

    if system_platform == 'Windows':
        rx_socket.bind(('', 0))

    reached = False
    recv_data_addr = []

    progress.update(receiver_task, total=n_hops*packets_to_repeat*3, visible=True)

    sender_done = False
    timed_out = False

    queue.put(True) # Indicate to the sender thread that receiver thread is ready

    while True:
        timed_out = False
        try:
            data, addr = rx_socket.recvfrom(1024)
            if addr[0] == host_ip:
                stop_queue.put(True)
            recv_data_addr.append((data, addr, time()))
            progress.update(receiver_task, advance=1)
        except error as e:
            timed_out = True
            #print(f'Timeout reached while some responses are still pending')
            try:
                sender_done = sync_queue.get(block=False)
            except:
                pass
        if sender_done and timed_out:
            break

    progress.update(receiver_task, completed=n_hops*packets_to_repeat*3)

    if not recv_data_addr:
        print(f'No responses received')
        progress.remove_task(receiver_task)
        return status

    recv_host_sport_udp = []
    recv_host_sport_tcp = []
    recv_host_ttl = []

    for data, addr, receive_time in recv_data_addr: # Parse received ICMP packets
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
        inner_ip_proto = int(inner_ip_header[18:20], 16)
        if inner_ip_proto == 1 and icmp_type == 11 and icmp_code == 0: # ICMP Time-to-live exceeded in transit
                inner_icmp_header = inner_ip_header[inner_ip_header_len:]
                inner_icmp_checksum = int(inner_icmp_header[4:8], 16)
                recv_host_ttl.append((resp_host, inner_icmp_checksum, None, receive_time)) # Store host and inner ICMP checksum
        elif icmp_type == 0 and icmp_code == 0 and resp_host == host_ip: # ICMP Echo reply
            icmp_data = icmp_header[16:len(icmp_header)]
            ttl = int(bytes.fromhex(icmp_data).decode().split(FLAG)[1]) # Retrieve TTL from sent data
            recv_host_ttl.append((resp_host, None, ttl, receive_time)) # Store host and TTL
            reached = True
        elif inner_ip_proto == 17:
            inner_udp_header = inner_ip_header[inner_ip_header_len:]
            inner_udp_len = int(inner_udp_header[8:12], 16) * 2
            inner_udp_header = inner_udp_header[:inner_udp_len]
            inner_udp_sport = int(inner_udp_header[0:4], 16)
            if icmp_type == 11 and icmp_code == 0: # ICMP Time-to-live exceeded in transit
                recv_host_sport_udp.append((resp_host, inner_udp_sport, receive_time))
            if icmp_type == 3 and icmp_code == 3 and resp_host == host_ip: # ICMP Destination unreachable Port unreachable
                recv_host_sport_udp.append((resp_host, inner_udp_sport, receive_time))
                reached = True
        elif inner_ip_proto == 6:
            inner_tcp_header = inner_ip_header[inner_ip_header_len:]
            inner_tcp_len = int(inner_tcp_header[8:12], 16) * 2
            inner_tcp_header = inner_tcp_header[:inner_tcp_len]
            inner_tcp_sport = int(inner_tcp_header[0:4], 16)
            if icmp_type == 11 and icmp_code == 0: # ICMP Time-to-live exceeded in transit
                recv_host_sport_tcp.append((resp_host, inner_tcp_sport, receive_time))
            if icmp_type == 3 and icmp_code == 3 and resp_host == host_ip: # ICMP Destination unreachable Port unreachable
                recv_host_sport_tcp.append((resp_host, inner_tcp_sport, receive_time))
                reached = True

    host_ttl_results, host_delta_time = map_received_icmp_to_sent_all(timeout, host, n_hops, host_ip, recv_host_sport_udp, recv_host_sport_tcp, recv_host_ttl, reached, queue)
    
    progress.remove_task(receiver_task)
    
    print_results(host_ttl_results, host_delta_time)

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
        help = 'Protocol to use: ICMP, UDP, TCP or ALL of them (default: ICMP)'
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
        type = float,
        action = 'store',
        default = 2,
        help = 'Timeout for responses (default: 2s)'
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

    protocol = args['protocol'].lower()
    if not (protocol == 'icmp' or protocol == 'udp' or protocol == 'tcp' or protocol == 'all'):
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
    
    timeout = float(args['timeout'])
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
                sync_queue = Queue()
                stop_queue = Queue()
            except Exception as e:
                print(f'Cannot start queues for thread information exchanges: {e}')
            try:
                with Progress() as progress:
                    sender_task = progress.add_task('Sending packets...', total=n_hops*packets_to_repeat, visible=False)
                    receiver_task = progress.add_task('Receiving packets...', total=n_hops*packets_to_repeat, visible=False)
                    rx_thread = Thread(target=receive_udp, args=(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, queue, sync_queue, stop_queue))
                    tx_thread = Thread(target=send_udp, args=(progress, sender_task, timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue, stop_queue))
                    rx_thread.start()
                    tx_thread.start()
                    tx_thread.join()
                    rx_thread.join()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')
        case 'tcp':
            print(f'flyingroutes to {host} ({host_ip}) with {n_hops} hops max ({packets_to_repeat} packets per hop) on TCP port {dst_port} with a timeout of {timeout}s')
            try:
                queue = Queue()
                sync_queue = Queue()
                stop_queue = Queue()
            except Exception as e:
                print(f'Cannot start queues for thread information exchanges: {e}')
            try:
                with Progress() as progress:
                    sender_task = progress.add_task('Sending packets...', total=n_hops*packets_to_repeat*2, visible=False)
                    receiver_task = progress.add_task('Receiving packets...', total=n_hops*packets_to_repeat, visible=False)
                    rx_thread = Thread(target=receive_tcp, args=(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, dst_port, queue, sync_queue, stop_queue))
                    tx_thread = Thread(target=send_tcp, args=(progress, sender_task, timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue, stop_queue))
                    rx_thread.start()
                    tx_thread.start()
                    tx_thread.join()
                    rx_thread.join()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')
        case 'all':
            print(f'flyingroutes to {host} ({host_ip}) with {n_hops} hops max ({packets_to_repeat} packets per hop) on ICMP, UDP port {dst_port} and TCP port {dst_port} with a timeout of {timeout}s')
            try:
                queue = Queue()
                sync_queue = Queue()
                stop_queue = Queue()
            except Exception as e:
                print(f'Cannot start queues for thread information exchanges: {e}')
            try:
                with Progress() as progress:
                    sender_task = progress.add_task('Sending packets...', total=n_hops*packets_to_repeat*3, visible=False)
                    receiver_task = progress.add_task('Receiving packets...', total=n_hops*packets_to_repeat*3, visible=False)
                    rx_thread = Thread(target=receive_all, args=(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, dst_port, queue, sync_queue, stop_queue))
                    tx_thread = Thread(target=send_all, args=(progress, sender_task, timeout, n_hops, host_ip, dst_port, packets_to_repeat, queue, sync_queue, stop_queue))
                    rx_thread.start()
                    tx_thread.start()
                    tx_thread.join()
                    rx_thread.join()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')
        case _:
            print(f'flyingroutes to {host} ({host_ip}) with {n_hops} hops max ({packets_to_repeat} packets per hop) on ICMP with a timeout of {timeout}s')
            try:
                queue = Queue()
                sync_queue = Queue()
                stop_queue = Queue()
            except Exception as e:
                print(f'Cannot start queues for thread information exchanges: {e}')
            try:
                with Progress() as progress:
                    sender_task = progress.add_task('Sending packets...', total=n_hops*packets_to_repeat, visible=False)
                    receiver_task = progress.add_task('Receiving packets...', total=n_hops*packets_to_repeat, visible=False)
                    rx_thread = Thread(target=receive_icmp, args=(progress, receiver_task, timeout, n_hops, host, host_ip, packets_to_repeat, queue, sync_queue, stop_queue))
                    tx_thread = Thread(target=send_icmp, args=(progress, sender_task, timeout, n_hops, host_ip, queue, sync_queue, stop_queue))
                    rx_thread.start()
                    tx_thread.start()
                    tx_thread.join()
                    rx_thread.join()
            except Exception as e:
                print(f'Cannot start sender and receiver threads: {e}')