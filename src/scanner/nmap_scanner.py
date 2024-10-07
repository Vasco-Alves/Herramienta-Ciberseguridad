import nmap

# Lista global que almacenará los hosts descubiertos
hosts_discovered = []


def scan_network(target="192.168.1.0/24", ports="22-443"):
    """
    Escanea la red usando Nmap y almacena los hosts detectados.

    :param target: Dirección IP o rango de IPs a escanear (por defecto toda la red local).
    :param ports: Rango de puertos a escanear (por defecto los puertos 22 a 443).
    :return: Resultados del escaneo en formato de texto.
    """
    global hosts_discovered
    hosts_discovered.clear()  # Limpiar la lista antes de un nuevo escaneo

    nm = nmap.PortScanner()
    print(f"Escaneando la red {target} en los puertos {ports}...")
    nm.scan(target, ports)

    scan_results = ""

    for host in nm.all_hosts():
        host_info = {
            "ip": host,
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "ports": [],
        }

        scan_results += (
            f"Host: {host} ({nm[host].hostname()}) - Estado: {nm[host].state()}\n"
        )

        for proto in nm[host].all_protocols():
            scan_results += f" Protocolo: {proto}\n"
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = {"port": port, "state": nm[host][proto][port]["state"]}
                host_info["ports"].append(port_info)
                scan_results += f"  Puerto: {port}\tEstado: {port_info['state']}\n"

        # Añadir host detectado a la lista global
        hosts_discovered.append(host_info)

    return scan_results
