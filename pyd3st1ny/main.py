from scapy.all import *
import time, os, netifaces, psutil, pyshark

def default_gateway_info():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET]
    
    addrs = netifaces.ifaddresses(default_gateway[1])
    
    cidr = sum(bin(int(x)).count("1") for x in addrs[netifaces.AF_INET][0]['netmask'].split("."))
    
    return str(default_gateway[0]+"/"+str(cidr))

def get_ips_tagets(server_dhcp_address):
    
    target = server_dhcp_address
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    
    for sent, received in result:
    # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        print("\r [+] Searching for IPs...", end="", flush=True)
        time.sleep(0.3)
    
    return clients

def main():
    
    try:

        os.system('cls' if os.name == 'nt' else 'clear')

        banner = str("\n ██████╗░██╗░░░██╗██████╗░██████╗░░██████╗████████╗░░███╗░░███╗░░██╗██╗░░░██╗" +
                "\n ██╔══██╗╚██╗░██╔╝██╔══██╗╚════██╗██╔════╝╚══██╔══╝░████║░░████╗░██║╚██╗░██╔╝" +
                "\n ██████╔╝░╚████╔╝░██║░░██║░█████╔╝╚█████╗░░░░██║░░░██╔██║░░██╔██╗██║░╚████╔╝░" +
                "\n ██╔═══╝░░░╚██╔╝░░██║░░██║░╚═══██╗░╚═══██╗░░░██║░░░╚═╝██║░░██║╚████║░░╚██╔╝░░" +
                "\n ██║░░░░░░░░██║░░░██████╔╝██████╔╝██████╔╝░░░██║░░░███████╗██║░╚███║░░░██║░░░" +
                "\n ╚═╝░░░░░░░░╚═╝░░░╚═════╝░╚═════╝░╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░\n")

        print(banner)

        # Get all network interfaces
        interfaces = psutil.net_if_addrs()
        # Get all network interfaces names
        interfaces_names = interfaces.keys()

        find_target = input(" [=] Find a local target. Type (y/n) for yes or no: ").lower()

        if find_target == "y":
            # get DHCP addresses using scapy
            print("\n [-] DHCP addresses and netmask:\n ---------------------------------")
            print(" [+]", default_gateway_info())
            print(" ---------------------------------\n")

            
            clients = get_ips_tagets(default_gateway_info())

            # get local IP addresses using scapy
            print("\n\n [-] Local IP addresses:\n ---------------------------------")

            for client in clients:
                print(" [+] {:16}    {}".format(client['ip'], client['mac']))
        
            print(" ---------------------------------\n")

        print("\n [-] Interfaces:\n ---------------------------------")
        for interface in interfaces_names:
            print(" [+] {}".format(interface))
        print(" ---------------------------------\n")

        interface_target = input("\n [=] Enter target interface: ")
        target_ip = input("\n [=] Enter target IP: ")

        packet_counter = 0
        print("\n [-] Packets:\n ---------------------------------")
        
        while True:
            capture = pyshark.LiveCapture(interface=interface_target)
            capture.sniff(timeout=10)
            for packet in capture.sniff_continuously(packet_count=10):
                packet_counter += 1
                try:
                    if packet.ip.src == target_ip or packet.ip.dst == target_ip:
                        print(" [-] Connection: {}".format(packet_counter))
                        print(" [+] source ip: {}".format(packet.ip.src))
                        print(" [+] destination ip: {}\n".format(packet.ip.dst))
                except AttributeError:
                    pass
            
    except KeyboardInterrupt:
        print("\n\n [-] Exiting...\n")
        exit()

if __name__ == "__main__":
    main()