import os
from scanner import nmap_scanner
from fuzzing import fuzzing
from mitm import mitm_attack


def is_root():
    if os.name == "nt":
        try:
            # En Windows, se considera administrador si puede usar net session
            return os.system("net session >nul 2>&1") == 0
        except Exception:
            return False
    else:
        # En Linux/Mac, verifica si el UID es 0 (root)
        return os.geteuid() == 0


def clear_console():
    if os.name == "nt":  # Para Windows
        os.system("cls")
    else:  # Para Linux y MacOS
        os.system("clear")


def show_menu():
    print("\n=== Herramienta de Ciberseguridad ===\n")
    print("1. Escaneo de Red Básico")
    print("2. Ver Hosts Detectados")
    print("3. Fuzzing de HTTP")
    if is_root():
        print("4. Ataque MITM")
    print("6. Salir")


def show_hosts():
    """
    Muestra los hosts decubiertos con el escaneo.
    """
    if len(nmap_scanner.hosts_discovered) == 0:
        print("\nNo se han detectado hosts aún. Realiza un escaneo primero.")
    else:
        print("\n--- Hosts Detectados ---")
        for i, host in enumerate(nmap_scanner.hosts_discovered, start=1):
            print(f"{i}. IP: {host['ip']}, Hostname: {host['hostname']}, Estado: {host['state']}")
            print("   Puertos Abiertos:")
            for port_info in host["ports"]:
                print(f"    - Puerto: {port_info['port']} | Estado: {port_info['state']}")
        print("------------------------")


def run_scanner():
    """
    Ejecuta el escaneo de red.
    """
    target = input("Introduce el objetivo de escaneo (IPs o rango de IPs): ")
    ports = input("Introduce el rango de puertos (por defecto 22-443): ")
    if not target:
        target = "192.168.1.0/24"
    if not ports:
        ports = "22-443"

    # Solicitar argumentos adicionales para Nmap
    print("\nIntroduce argumentos adicionales para Nmap (por defecto: '-sS') o deja vacío para un escaneo estándar.")
    extra_arguments = input("Argumentos adicionales: ")
    if not extra_arguments:
        extra_arguments = "-sS"  # Escaneo SYN por defecto

    # Realizar el escaneo con los argumentos adicionales proporcionados
    scan_results = nmap_scanner.scan_network(target, ports, extra_arguments)
    print("\n--- Resultados del Escaneo ---")
    print(f"\n{scan_results}")

    # Opción para guardar los resultados
    save_choice = input("¿Deseas guardar los resultados en un archivo? (s/n): ")
    if save_choice.lower() == "s":
        filename = (input("Introduce el nombre del archivo (por defecto 'scan_results.txt'): ") or "scan_results.txt")
        nmap_scanner.save_scan_results(scan_results, filename)


def run_fuzzing():
    """
    Ejecuta el fuzzing por HTTP.
    """
    url = input("Introduce la URL objetivo para el fuzzing (ej. http://localhost): ")
    dictionary_path = input("Introduce la ruta al archivo de diccionario (por defecto 'dictionary.txt'): ")
    num_requests = input("Introduce el número de peticiones de fuzzing (por defecto 10): ")

    if not dictionary_path:
        dictionary_path = "dictionary.txt"
    if not num_requests.isdigit():
        num_requests = 10
    else:
        num_requests = int(num_requests)

    fuzzing.fuzz_http(url, dictionary_path, num_requests)


def run_mitm_attack():
    """
    Ejecuta el ataque MITM (Man-in-the-Middle) con ARP spoofing.
    """
    gateway_ip = input("Introduce la IP del gateway (router): ")
    victim_ip = input("Introduce la IP de la víctima: ")

    if not gateway_ip or not victim_ip:
        print("[!] Debes proporcionar las IPs del gateway y la víctima.")
        return

    # Valida que ambas IPs sean válidas
    if not nmap_scanner.validate_ip(gateway_ip) and not nmap_scanner.validate_ip(victim_ip):
        print("[!] Las IPs no están bien definidas.")
        return

    print(f"[+] Preparando ataque MITM entre el gateway {gateway_ip} y la víctima {victim_ip}...")
    try:
        mitm_attack.mitm_attack(gateway_ip, victim_ip)

    except KeyboardInterrupt:
        print("[!] Ataque detenido por el usuario.")


def main():
    try:
        while True:
            clear_console()
            show_menu()
            choice = input("\nElige una opción: ")

            if choice == "1":
                print("\n--- Escaneo de Red Básico ---")
                run_scanner()
            elif choice == "2":
                show_hosts()
            elif choice == "3":
                print("\n--- Fuzzing de HTTP ---")
                run_fuzzing()
            elif choice == "4" and is_root():
                print("\n--- Ataque Man-in-the-Middle ---")
                run_mitm_attack()
            elif choice == "6":
                print("\nSaliendo de la herramienta. ¡Hasta pronto!")
                break
            else:
                print("\nOpción no válida. Por favor, elige una opción del menú.")
            input("\nPresiona Enter para continuar...")  # Pausa antes de limpiar la pantalla

    except KeyboardInterrupt:
        print("\n\n[!] Aplicación interrumpida por el usuario. Saliendo...")


if __name__ == "__main__":
    main()
