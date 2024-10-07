# from scanner import nmap_scanner
# from mitm import mitm_attack
# from fuzzing import fuzzing
# from traffic_capture import capture
from scanner import nmap_scanner


def show_menu():
    print("\n=== Herramienta de Ciberseguridad ===")
    print("1. Escaneo de Red")
    print("2. Ataque MITM (Man-in-the-Middle)")
    print("3. Fuzzing")
    print("4. Captura de Tráfico")
    print("5. Ver Hosts Detectados")
    print("6. Salir")
    print("=====================================")


def run_scanner():
    target = input(
        "Introduce el objetivo de escaneo (IP o rango de IPs, ej. 192.168.1.0/24): "
    )
    ports = input("Introduce el rango de puertos (por defecto 22-443): ")

    if not target:
        target = "192.168.1.0/24"
    if not ports:
        ports = "22-443"

    scan_results = nmap_scanner.scan_network(target=target, ports=ports)
    print(scan_results)


def show_hosts():
    if len(nmap_scanner.hosts_discovered) == 0:
        print("\nNo se han detectado hosts aún. Realiza un escaneo primero.")
    else:
        print("\n--- Hosts Detectados ---")
        for i, host in enumerate(nmap_scanner.hosts_discovered, start=1):
            print(
                f"{i}. IP: {host['ip']}, Hostname: {host['hostname']}, Estado: {host['state']}"
            )
        print("------------------------")


def run_mitm_attack():
    if len(nmap_scanner.hosts_discovered) == 0:
        print(
            "\nNo se pueden ejecutar ataques MITM. Realiza primero un escaneo para detectar hosts."
        )
    else:
        print("\n--- Ataque MITM ---")
        # Aquí se implementará la lógica del ataque MITM
        show_hosts()
        target_index = int(input("Selecciona el número del host objetivo: ")) - 1
        if 0 <= target_index < len(nmap_scanner.hosts_discovered):
            target_host = nmap_scanner.hosts_discovered[target_index]
            print(
                f"Ejecutando MITM contra {target_host['ip']} ({target_host['hostname']})..."
            )
            # Llamar a la función que ejecuta el ataque MITM
        else:
            print("Selección inválida.")


def main():
    while True:
        show_menu()
        choice = input("\nElige una opción: ")

        if choice == "1":
            print("\n--- Escaneo de Red ---")
            run_scanner()
        elif choice == "2":
            run_mitm_attack()
        elif choice == "3":
            print("\n--- Fuzzing (Próximamente) ---")
        elif choice == "4":
            print("\n--- Captura de Tráfico (Próximamente) ---")
        elif choice == "5":
            show_hosts()
        elif choice == "6":
            print("\nSaliendo de la herramienta. ¡Hasta pronto!")
            break
        else:
            print("\nOpción no válida. Por favor, elige una opción del menú.")


if __name__ == "__main__":
    main()
