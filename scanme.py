#Tool made by oussama baccara aka ignorant05.
#Copyright disclaimer : This tool runs under my name, so please don't be silly and copy the code and act like it's yours...If you do then idc.
#Usage only for ethical purposes and i don't recognise any unethical usage.

##############################################################################################################################################################################

#! /usr/bin/env python3

##############################################################################################################################################################################

import socket 
from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.layers.inet import ICMP

from prettytable import PrettyTable

import threading 
import resource
import struct

import argparse
import re

import logging 

##############################################################################################################################################################################

class Display : 

    def status(open_ports, closed_ports, filtered_ports):
        table = PrettyTable()
        table.field_names=["Open Ports", "Closed Ports", "Filtered Ports"]

        open_ports_Display = list(map(str, open_ports)) if open_ports else ["-"]
        closed_ports_Display = list(map(str, closed_ports)) if closed_ports else ["-"]
        filtered_ports_Display = list(map(str, filtered_ports)) if filtered_ports else ["-"]

        max_length =max(len(open_ports_Display), len(closed_ports_Display), len(filtered_ports_Display))

        for i in range(max_length):
           
            open_port = open_ports_Display[i] if i < len(open_ports_Display) else "-"
            closed_port = closed_ports_Display[i] if i < len(closed_ports_Display) else "-"
            filtered_port = filtered_ports_Display[i] if i < len(filtered_ports_Display) else "-"
            
            table.add_row([open_port, closed_port, filtered_port])

        print(table)
        logging.info("Scan complete")
 
##############################################################################################################################################################################

class Check : 

    @staticmethod
    def check_IP (target):
        pattern = r"\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\."\
                  r"\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\."\
                  r"\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\."\
                  r"\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
        
        return re.search(pattern, target)

    @staticmethod
    def check_port(port):

        return True if port in range(1,65535) else False 
     
##############################################################################################################################################################################

class ParsingArguments : 

    @staticmethod    
    def parse_arguments():

        tool_decription = """This Python-based port scanner allows users to efficiently scan network ports on a target system using multiple scanning techniques. With multi-threading capabilities, it supports various scan types including TCP Connect, SYN, UDP, FIN, XMAS, NULL, ACK, and Window scans. The tool is designed to be both fast and flexible, allowing users to customize the number of threads, timeout values, and port ranges. It's suitable for network reconnaissance and identifying open, closed, or filtered ports while providing a user-friendly output."""

        parser = argparse.ArgumentParser(
            description=tool_decription,
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument(
            "--scan", type = str, required=True, help="Scan types to perform: tcp,syn,udp,fin,xmas,null,ack,window"
            )
        parser.add_argument(
            "--target", type=str, required=True, help="Target IP address"
        )
        parser.add_argument(
            "--ports", type=str, required=True, help="Single port, multiple ports (comma-separated), or range (e.g., 80,443 or 20-80"
        )
        parser.add_argument(
            "--threads", type=int, default=100, help="Number of threads (default: 100)"
        )
        parser.add_argument(
            "--timeout", type=int, default=10, help="Timeout value for each scan (default: 10)"
        )
        return parser.parse_args()
    
    @staticmethod
    def parse_ports(ports_string):

        ports = set()
        for p in ports_string.split(",") :
            if '-' in p :
                start, end = p.split("-")
                ports.update(range(int(start), int(end)+1))
            else : 
                ports.add(int(p))
        return sorted(ports)

##############################################################################################################################################################################

class ErrorHandling: 

    @staticmethod
    def handle_socket_error(port, e):
        if e.errno == 101:  
            print(f"Network unreachable for port {port}.")
        elif e.errno == 111:
            print(f"[-] No response on port {port} (could be filtered or closed)")
        else:
            print(f"[-] Error on port {port}: {e}")
    
    @staticmethod
    def IP_error(target):
        if Check.check_IP(target) == False:
            print(f"{target} is not a valid IP addres.")
    
    @staticmethod
    def port_error(port):
        if Check.check_port(port) == False :
            print(f"{port} is not a valid port number detercter.")

##############################################################################################################################################################################

class Multithreading:

    def __init__(self, target, list_of_ports , threads_number, time_out):

        self.logger = logging.Logger(__name__)
        self.target=target
        self.list_of_ports = list_of_ports
        self.threads_number=threads_number
        self.time_out=time_out

        self.lock = threading.Lock()

        self.open_ports=[]
        self.closed_ports=[]
        self.filtered_ports=[]
        
        max_os_threads = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        self.max_threads = min (self.threads_number, max_os_threads)

    def MultithreadingScan(self, scan_type):
        threads = []

        scan_class = {
            'tcp': TCPScan,
            'udp': UDPScan,
            'syn': SYNScan,
            'fin': FINScan,
            'xmas': XMASScan,
            'null': NULLScan,
            'ack': ACKScan,
            'window': WindowScan
        }

        if scan_type not in scan_class:
            logging.error(f"[!] Unsupported scan type.")
            return
        
        l = len(self.list_of_ports)
        scanner = scan_class[scan_type](self.target, self.list_of_ports, self.threads_number, self.time_out, self.open_ports, self.closed_ports, self.filtered_ports, self.lock)

        for idx, port in enumerate(self.list_of_ports):
            
            thread = threading.Thread(target=scanner.scan_port, args=(port,))
            threads.append(thread)
            thread.start()

            logging.info(f"Scanning port {port}...")
            
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()  
                threads = []  
            logging.info(f"Scanned {idx + 1}/{l} ports...")
        
        for t in threads:
            t.join()

        print("All threads have completed.")
        Display.status(self.open_ports, self.closed_ports, self.filtered_ports)
        
    def scan_port(self, port):
        raise NotImplementedError("Subclasses must implement this method.")
        
##############################################################################################################################################################################

class TCPScan(Multithreading) :

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port (self, port):
    
        try : 
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s :
                s.settimeout(self.time_out)

                response = s.connect_ex((self.target,port))
                with self.lock: 
                    if response == 0 :
                    
                        self.open_ports.append(str(port))
                        logging.info(f"Port {port} is open.")
                    else :
                    
                        self.closed_ports.append(str(port))
                        logging.info(f"Port {port} is closed.")
            
        except socket.timeout:
            pass

        except(PermissionError, socket.error )as e:
            print(f"[!] TCP Error on port {port}: {e}")

##############################################################################################################################################################################

class UDPScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port(self, port):
    
        try : 
    
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s :
                s.settimeout(self.time_out) 
                s.sendto(b"test", (self.target, port))
                data , addr = s.recvfrom(1024)
                with self.lock:
                    if data : 
                        if not self.icmp_unreachable(data):
                            self.open_ports.append(port)
                        else:
                            self.closed_ports.append(port)

        except socket.timeout:
            pass
        except socket.error as e:
            ErrorHandling.handle_socket_error(port,e)
        except Exception as e:
            logging.error(f"[-] Something went wrong on port {port}: {e}")
        
    def icmp_unreachable(self,data):
        if len(data)< 28 :
            return False
        icmp_header = data[20:28]  
        type_, code, checksum = struct.unpack('!BBH', icmp_header[:4])
    
        return type_ == 3 and (code == 1 or code == 3)
            
##############################################################################################################################################################################

class SYNScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port (self,port):
        
        try :
            packet = IP(dst=self.target)/TCP(dport=port, flags="S" ) 
            response = sr1(packet, timeout=self.time_out, verbose=0)
            with self.lock:
                if response is None:
                    self.filtered_ports.append(port)
                elif response.haslayer(TCP):
                    if response[TCP].flags ==0x12:
                        self.open_ports.append(port)
                    elif response[TCP].flags == 0x14 :
                        self.closed_ports.append(port)
                elif response.haslayer(ICMP) :
                    self.filtered_ports.append(port)
        except socket.timeout:
            pass
        except PermissionError as e:
            logging.error(f"[!] Permission error on port {port}: {e}")

        except socket.error as e:
            ErrorHandling.handle_socket_error(port, e)
    
##############################################################################################################################################################################

class FINScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port(self, port):
        try : 
            packet = IP(dst=self.target)/TCP(dport=port, flags="F")
            response = sr1(packet, timeout=self.time_out, verbose=0)
            with self.lock:
                if response is None:
                    self.filtered_ports.append(port)
                elif response.haslayer(TCP):
                    if response[TCP].flags ==0x14:
                        self.closed_ports.append(port)
                    else :
                        self.open_ports.append(port)
                elif response.haslayer(ICMP) :
                    self.filtered_ports.append(port)
                
        except socket.timeout:
            pass
        except PermissionError as e:
            logging.error(f"[!] Permission error on port {port}: {e}")

        except socket.error as e:
            ErrorHandling.handle_socket_error(port, e)

##############################################################################################################################################################################

class XMASScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock
    
    def scan_port(self, port):
        try : 
            packet = IP(dst=self.target)/TCP(dport=port, flags="FUP")
            response = sr1(packet, timeout=self.time_out, verbose=0)
            with self.lock:
                if response is None:
                    self.filtered_ports.append(port)
                elif response.haslayer(TCP):
                    if response[TCP].flags ==0x14:
                        self.closed_ports.append(port)
                    else :
                        self.open_ports.append(port)
                elif response.haslayer(ICMP) :
                    self.filtered_ports.append(port)

        except socket.timeout:
            pass
        except PermissionError as e:
            logging.error(f"[!] Permission error on port {port}: {e}")

        except socket.error as e:
            ErrorHandling.handle_socket_error(port, e)

##############################################################################################################################################################################

class NULLScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port(self, port):
        try : 
            packet = IP(dst=self.target)/TCP(dport=port)
            response = sr1(packet, timeout=self.time_out, verbose=0)
            with self.lock:
                if response is None:
                    self.filtered_ports.append(port)
                elif response.haslayer(TCP):
                    if response[TCP].flags ==0x14:
                        self.closed_ports.append(port)
                    else :
                        self.open_ports.append(port)
                elif response.haslayer(ICMP) :
                    self.filtered_ports.append(port)

        except socket.timeout:
            pass
        except PermissionError as e:
            logging.error(f"[!] Permission error on port {port}: {e}")
        except socket.error as e:
            ErrorHandling.handle_socket_error(port, e)

##############################################################################################################################################################################

class ACKScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port(self, port):
        
        try :
            packet = IP(dst=self.target)/TCP(dport=port, flags="A")
            response = sr1(packet,timeout=self.time_out, verbose=0)
            with self.lock:
                if response ==None  or response.haslayer(ICMP):
                    self.filtered_ports.append(port)
                elif response.haslayer(TCP) :
                    if response[TCP].flags ==0x14 : 
                        self.closed_ports.append(port)
        except socket.timeout:
            pass
        except PermissionError as e:
            logging.error(f"[!] Permission error on port {port}: {e}")

        except socket.error as e:
            ErrorHandling.handle_socket_error(port, e)

##############################################################################################################################################################################

class WindowScan(Multithreading):

    def __init__(self, target, list_of_ports, threads_number, time_out, open_ports, closed_ports, filtered_ports, lock):
        super().__init__(target, list_of_ports, threads_number, time_out)
        self.open_ports = open_ports
        self.closed_ports = closed_ports
        self.filtered_ports = filtered_ports
        self.lock = lock

    def scan_port(self, port):
        try :
            packet = IP(dst=self.target)/TCP(dport=port, flags= "S")
            response = sr1(packet, timeout=self.time_out, verbose = 0)
            with self.lock:
                if response is None :
                    self.closed_ports.append(port)
                elif response.haslayer(TCP): 
                    self.open_ports.append(port)
                elif response.haslayer(ICMP):
                    self.filtered_ports.append(port)
        
        except socket.timeout : 
            pass
        except socket.error as e:
            ErrorHandling.handle_socket_error(port, e)

##############################################################################################################################################################################

if __name__ =="__main__":

    logging.basicConfig(
        level=logging.INFO,  
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("port_scanner.log"),  
            logging.StreamHandler() 
        ]
    )

    args = ParsingArguments.parse_arguments()
    scan_type=args.scan.strip(",")
    list_of_ports = ParsingArguments.parse_ports(args.ports)

    ErrorHandling.IP_error(args.target)
    
    for port in list_of_ports :
        ErrorHandling.port_error(port)
    
    scanner = Multithreading(
        target=args.target,
        list_of_ports=list_of_ports,
        threads_number=int(args.threads),
        time_out=int(args.timeout)
    )
    scanner.MultithreadingScan(scan_type)
    logging.info(f"The number of ports scanned is: {len(list_of_ports)}/{len(list_of_ports)} ")
    
##############################################################################################################################################################################
