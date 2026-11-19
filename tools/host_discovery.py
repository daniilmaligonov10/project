from scapy.all import ARP, Ether, srp
import errno
import psutil
import ipaddress
import socket
import re

DEFAULT_PORTS = [21, 22, 23, 80, 443, 554, 8080]
PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    443: "https",
    554: "rtsp",
    8080: "http-proxy",
}


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
        network_name, _, network = networks[0]
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

def scan_ports(host, ports=None):
    if ports is None:
        ports = DEFAULT_PORTS
    scanned_ports = []
    # opened_ports = []
     # closed_ports=[]

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            
        if result == 0:
            status = "open"
        elif result == errno.ECONNREFUSED:
            status = "closed"
        else:
            status = "no_response"

        scanned_ports.append({
            "port": port,
            "service": PORT_NAMES.get(port, "unknown"),
            "status": status,
        })

    return scanned_ports
        
def inspect_service(host,ports):
    inspection_result = []
    for port in ports:
        service = "unknown"
        version = "unknown"
        name = "unknown"
        banner = ""
        try:
            with socket.create_connection((host, port), timeout=2) as s:
                s.settimeout(2)
                try:
                    raw_banner = s.recv(1024)
                    banner = raw_banner.decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    banner = ""

            if banner.startswith("SSH-"):
                name = "SSH"
                info = banner.split("-", 2)[2]
                if "_" in info:
                    service, version = info.rsplit("_", 1)
                else:
                    service = info
                if not banner or port in (80,8080):
                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    )
                    s.sendall(request.encode("ascii"))

                    http_text = response.decode("utf-8", errors="replace")
                    
                    for line in http_text.splitlines():
                        if line.lower().startswith("server:"):
                            value = line.split(":", 1)[1].strip()

                            if "/" in value:
                                service,version = value.split("/", 1)
                            else:
                                service = value
                            break

        except OSError:
            pass

        inspection_result.append({
            "port": port,
            "name": name,
            "service": service,
            "version": version,
        })

    return inspection_result


                





                
                  

   
        
        





            
