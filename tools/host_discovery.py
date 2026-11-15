from scapy.all import ARP, Ether, srp
import psutil
import ipaddress
import socket


def find_local_networks():
    networks = []
    for name,addresses in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        if stats is None or not stats.isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            interface = ipaddress.ip_interface( f'{address.address}/{address.netmask}')

            if interface.ip.is_loopback or interface.ip.is_link_local:
                continue
            networks.append((name, interface.ip, interface.network))

    if not networks:
        return("no ip4 networks found")
    if len(networks) != 1:
        return(networks)
    else:
        network_name, _, network = network[0]
        return scan_network(network, network_name)
        
        
def scan_network(target_ip, interface_name):
    arp = ARP(pdst=str(target_ip))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, iface=interface_name, timeout=5, verbose=0)[0]
    clients = []

    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    return clients



            
