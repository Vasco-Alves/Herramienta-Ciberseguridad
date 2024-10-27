import nmap
import ipaddress
from colorama import Fore, Style

# Lista global que almacenará los hosts descubiertos
hosts_discovered = []


def validate_ip(target):
    """
    Verifica si la dirección IP o el rango de IPs es válido.
    """
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def validate_ports(ports):
    """
    Verifica que el rango de puertos sea válido.
    """
    try:
        port_range = ports.split("-")
        if len(port_range) == 2:
            port_start, port_end = int(port_range[0]), int(port_range[1])
            return (
                0 <= port_start <= 65535
                and 0 <= port_end <= 65535
                and port_start <= port_end
            )
        elif len(port_range) == 1:
            return 0 <= int(port_range[0]) <= 65535
        else:
            return False
    except ValueError:
        return False


def scan_network(target="192.168.1.0/24", ports="22-443", arguments="-sS"):
    """
    Escanea la red usando Nmap y almacena los hosts detectados.

    :param target: Dirección IP o múltiples IPs/rangos separados por comas.
    :param ports: Rango de puertos a escanear (por defecto los puertos 22 a 443).
    :param arguments: Argumentos adicionales de Nmap (por defecto '-sS').
    :return: Resultados del escaneo en formato de texto.
    """
    global hosts_discovered
    hosts_discovered.clear()  # Limpiar la lista antes de un nuevo escaneo

    # Verificar entradas
    if not validate_ip(target):
        return f"[!] Error: Una o más direcciones IP o rangos son inválidos: {target}"
    if not validate_ports(ports):
        return f"[!] Error: Rango de puertos inválido: {ports}"

    nm = nmap.PortScanner()
    targets = target.split(",")  # Separar las IPs/rangos por comas

    scan_results = ""
    for ip in targets:
        ip = ip.strip()  # Eliminar espacios en blanco alrededor de las IPs

        print(
            f"Ejecutando escaneo en {ip} con puertos {ports} y argumentos '{arguments}'..."
        )

        # Realizar el escaneo con los argumentos adicionales proporcionados
        try:
            nm.scan(ip, ports, arguments=arguments)
        except nmap.PortScannerError as e:
            return f"[!] Error de Nmap: {str(e)}"
        except Exception as e:
            return f"[!] Ocurrió un error inesperado: {str(e)}"

        # Mostrar el comando exacto ejecutado por Nmap
        print(f"\nComando ejecutado: {nm.command_line()}")

        # Procesar y mostrar resultados del escaneo
        for host in nm.all_hosts():
            host_info = {
                "ip": host,
                "hostname": nm[host].hostname(),
                "state": nm[host].state(),
                "ports": [],
            }

            scan_results += f"{Fore.BLUE}Host: {host} ({nm[host].hostname()}) - Estado: {nm[host].state()}{Style.RESET_ALL}\n"

            # Mostrar sistema operativo si se usa -O
            if "osclass" in nm[host]:
                scan_results += (f"{Fore.YELLOW}[+] Sistema operativo detectado:{Style.RESET_ALL}\n")
                for osclass in nm[host]["osclass"]:
                    scan_results += f"  - {osclass['osfamily']} ({osclass['osgen']}) - Precisión: {osclass['accuracy']}%\n"

            for proto in nm[host].all_protocols():
                scan_results += f" Protocolo: {Fore.BLUE}{proto}{Style.RESET_ALL}\n"
                lport = nm[host][proto].keys()
                for port in lport:
                    port_info = {"port": port, "state": nm[host][proto][port]["state"]}
                    host_info["ports"].append(port_info)

                    # Colorear según el estado del puerto
                    if port_info["state"] == "open":
                        service = nm[host][proto][port].get("name", "Unknown service")
                        version = nm[host][proto][port].get("version", "Unknown version")
                        scan_results += f"  Puerto: {Fore.GREEN}{port_info['port']}{Style.RESET_ALL}\tEstado: {Fore.GREEN}Abierto{Style.RESET_ALL}\n"
                        scan_results += f"  Servicio: {Fore.CYAN}{service}{Style.RESET_ALL}\tVersión: {Fore.CYAN}{version}{Style.RESET_ALL}\n\n"

            # Añadir host detectado a la lista global
            hosts_discovered.append(host_info)

    return scan_results


def save_scan_results(scan_results, filename="scan_results.txt"):
    """
    Guarda los resultados del escaneo en un archivo de texto sin códigos de color.
    """
    try:
        clean_results = remove_ansi_escape_sequences(scan_results)
        with open(filename, "w") as f:
            f.write(clean_results)
        print(f"Resultados guardados en {filename}")
    except Exception as e:
        print(f"[!] Error al guardar los resultados: {str(e)}")


import re


def remove_ansi_escape_sequences(text):
    """
    Elimina los códigos de escape ANSI (colores) del texto.
    """
    ansi_escape = re.compile(r"(?:\x1B[@-_][0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)
