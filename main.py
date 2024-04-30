import argparse
import ipaddress
import threading
import logging

from queue import Queue
from scapy.all import *
from scapy.layers.inet import *
from hostClass import HostUp

# don't display warning scapy.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


############################################################################################################
# Main function
############################################################################################################

def main():
    """The main function for the network scanning program."""

    # Create an ArgumentParser object
    parser = argparse.ArgumentParser(
        description="Scan a subnet for hosts, identify their MAC addresses, operating systems, and open ports."
    )

    # Define required and optional arguments
    parser.add_argument(
        "-s",
        "--subnet",
        type=str,
        required=True,
        help="An IP address in CIDR notation defining the subnet to scan.",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=15,
        help="Number of threads to use for ping scanning (default: 15).",
    )
    parser.add_argument(
        "-ps", "--portStart", type=int, default=0, help="Starting port to scan (default: 0)."
    )
    parser.add_argument(
        "-pe", "--portEnd", type=int, default=500, help="Ending port to scan (default: 500)."
    )

    # Parse arguments
    args = parser.parse_args()

    # Validate port range (optional):
    if args.portStart < 0 or args.portStart > args.portEnd:
        print("Error: Port range invalid. Starting port must be less than or equal to ending port.")
        return
    
    list_Hosts = []
    ports_to_check = range(args.portStart,args.portEnd)
    
    # Get the list of up hosts
    print(f"Scanning subnet {args.subnet} with {args.threads} threads... \n")
    icmp_ping_multithreaded(args.subnet, args.threads, list_Hosts)


    print(f"\nScanning ports {args.portStart} to {args.portEnd}... \n")
    # Get the MAC address, OS, and open ports for each host
    for i in list_Hosts:
        mac = scanMac(i.ip)
        HostUp.add_mac(i,mac_addr=str(mac))
        osScanned = scanOS(i.ip)
        HostUp.add_os(i,os=osScanned)
        for g in scanPorts(i.ip, ports_to_check):
            HostUp.add_port(i,port=g)
    
        print(f"[+] IP: {i.ip}, MAC:",format(i.mac_addr))
        print(f"[+] OS: {i.os}")
        print(f"[+] Ports: {i.ports}")
        print("\n\n")

############################################################################################################
# Function to scan up IPs on the network
############################################################################################################

def ping_thread(ip_queue: Queue,counter: int, list_Hosts: list):
    """Thread function to perform ping requests and initiate port scans."""
    while not ip_queue.empty():
        ip_addr = ip_queue.get()
        # Send ICMP request to IP address and wait for response to determine if host is up
        try:
            ans, unans = sr(IP(dst=str(ip_addr))/ICMP(), timeout=1, verbose=0) 
            if not unans: 
                # Host is up so add it to the list
                counter = HostUp(ip=str(ip_addr))
                list_Hosts.append(counter)
        except Exception as e:
            print(f"Error processing {ip_addr}: {e}")
        ip_queue.task_done()


############################################################################################################
# Function multithreaded to scan up IPs on the network
############################################################################################################

def icmp_ping_multithreaded(netmask: str, num_threads: int, list_Hosts: list = []):
    """ICMP Ping scan with multithreading and separate port scan threads."""
    ip_queue = Queue()
    threads = []
    # Define the threading_counter variable
    threading_counter = 0

    # Add all IP addresses in the network to the queue
    for ip_addr in ipaddress.IPv4Network(netmask):
        ip_queue.put(ip_addr)

    # Create and start the threads
    for _ in range(num_threads):
        threading_counter += 1
        thread = Thread(target=ping_thread, args=(ip_queue, threading_counter, list_Hosts))
        thread.start()
        threads.append(thread)

    # Wait for all IP addresses to be processed
    ip_queue.join()  

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print("All threads finished.")
    return list_Hosts

############################################################################################################
# Function to scan MAC address of the up IPs on the network
############################################################################################################

def scanMac(ip):
    # Send ARP request to IP address and wait for response to determine MAC address
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    # Return the MAC address if found, otherwise return "Unknown"
    for snd,rcv in ans:
        mac = rcv[Ether].src
        return mac
    return "Unknown"

############################################################################################################
# Function to scan OS of the up IPs on the network
############################################################################################################
def scanOS(ip):
    # Send ICMP request to IP address and wait for response to determine OS
    ans = sr1(IP(dst=str(ip))/ICMP(), timeout=3, verbose=0)
    # Return the OS if found, otherwise return "Unknown"
    if ans:
        # Check the TTL value to determine the OS
        if IP in ans:
            ttl=ans.getlayer(IP).ttl
            if ttl <= 64:
                return "Linux"
            else:
                return "Windows"
    return "Unknown"

############################################################################################################
# Function to scan open ports of the up IPs on the network
############################################################################################################

def scanPorts(ip, portRange):

    thread_number=15
    # Create a list to store the open ports and a queue to store the ports to scan
    port_queue = Queue()
    list_port_open=[]

    # Create a dictionary to store the port status
    tcp_port_dict = {}

    # Create threads to scan the ports
    for i in range(thread_number):		
        thread = Thread(target=scanTCPPort, args = (ip, tcp_port_dict, port_queue))
        thread.daemon = True
        thread.start()

    # Add the ports to the queue
    for port in portRange:
        port_queue.put(port)

    # Wait for all ports to be scanned
    port_queue.join()	

    # Add the open ports to the list
    for port in sorted(tcp_port_dict):
        if tcp_port_dict[port] == "Open":
            list_port_open.append(port)

    return list_port_open

############################################################################################################
# Function to scan TCP ports
############################################################################################################
def scanTCPPort(ip, port_dict, queue):
     
    # Send SYN packet to the port and wait for response to determine if port is open
	while True:

		dst_port = queue.get()
		src_port = RandShort()
    
        # Send SYN packet to the port
		ans = sr1(IP(dst=ip)/TCP(sport=src_port, dport=dst_port, flags="S"), timeout=2, verbose=False)

        # Check the response to determine if the port is open
		if ans is None:
			port_dict[dst_port]="Closed"
    
        
		elif(ans.haslayer(TCP)):

			# If the packet returned had the SYN and ACK flags
			if(ans.getlayer(TCP).flags == 0x12):
				# Send a RST packet to close the connection
				ans = sr1(IP(dst=ip)/TCP(sport=src_port,dport=dst_port,flags=0x14), timeout=2, verbose=False)

				port_dict[dst_port]="Open"

			# If the packet returned had the RST and ACK flags
			elif (ans.getlayer(TCP).flags == 0x14):
				port_dict[dst_port]="Closed"
		else:
			port_dict[dst_port]="Closed"

		queue.task_done()
          

############################################################################################################
# Main
############################################################################################################

if __name__ == '__main__':
    main()
