from scapy.all import sniff, wrpcap


def capture_traffic(filter="ip", count=0, output_file=None, stop_event=None):
    """
    Captura tráfico de red basado en un filtro y opcionalmente lo guarda en un archivo PCAP.

    :param filter: Filtro BPF para capturar tráfico (por defecto "ip").
    :param count: Número de paquetes a capturar (0 = infinito).
    :param output_file: Ruta del archivo PCAP donde se guardará el tráfico (opcional).
    :param stop_event: threading.Event para detener la captura.
    """
    print(f"[+] Iniciando captura de tráfico con el filtro: {filter}")
    captured_packets = []

    def process_packet(packet):
        if stop_event and stop_event.is_set():  # Detener si el evento está activado
            return False  # Detener el sniffing
        print(packet.summary())  # Mostrar resumen en la terminal
        captured_packets.append(packet)

    sniff(
        filter=filter,
        prn=process_packet,
        store=False,
        count=count,
        stop_filter=lambda x: stop_event and stop_event.is_set(),
    )

    if output_file:
        print(f"[+] Guardando {len(captured_packets)} paquetes en {output_file}...")
        wrpcap(output_file, captured_packets)  # Guardar los paquetes en un archivo PCAP
        print(f"[+] Captura guardada en {output_file}.")


# from scapy.all import sniff, wrpcap


# def capture_traffic(filter="ip", count=0, output_file=None, stop_event=None):
#     """
#     Captura tráfico de red basado en un filtro y opcionalmente lo guarda en un archivo PCAP.

#     :param filter: Filtro BPF para capturar tráfico (por defecto "ip").
#     :param count: Número de paquetes a capturar (0 = infinito).
#     :param output_file: Ruta del archivo PCAP donde se guardará el tráfico (opcional).
#     :param stop_event: threading.Event para detener la captura.
#     """
#     print(f"[+] Iniciando captura de tráfico con el filtro: {filter}")
#     captured_packets = []

#     try:
#         def process_packet(packet):
#             if stop_event and stop_event.is_set():  # Detener si el evento está activado
#                 raise KeyboardInterrupt
#             print(packet.summary())  # Mostrar resumen en la terminal
#             captured_packets.append(packet)

#         sniff(filter=filter, prn=process_packet, store=False, count=count, stop_filter=lambda x: stop_event.is_set())

#     except KeyboardInterrupt:
#         print("\n[!] Captura de tráfico interrumpida por el usuario.")

#     finally:
#         if output_file:
#             print(f"[+] Guardando {len(captured_packets)} paquetes en {output_file}...")
#             wrpcap(output_file, captured_packets)  # Guardar los paquetes en un archivo PCAP
#             print(f"[+] Captura guardada en {output_file}.")
