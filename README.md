# Herramienta de Ciberseguridad

## Descripción

Esta herramienta de ciberseguridad multiusos está diseñada para realizar tareas esenciales como:

- **Escaneo de red**: Detectar dispositivos activos, puertos abiertos, servicios en ejecución, y en algunos casos, sistemas operativos.
- **Fuzzing HTTP**: Probar servicios web en busca de vulnerabilidades mediante palabras predefinidas en un diccionario.
- **Ataque MITM (Man-in-the-Middle)**: Interceptar y analizar tráfico de red utilizando ARP spoofing.
- **Captura de tráfico**: Recopilar y guardar tráfico de red en un archivo PCAP para su análisis.

Esta herramienta está diseñada con fines educativos y debe usarse exclusivamente en entornos de prueba y con autorización.

---

## Instalación

### Requisitos

- **Python 3.8+**
- Sistema operativo basado en Linux (para ejecutar ataques MITM correctamente).
- Acceso a permisos de **root** para algunas funcionalidades (como el ataque MITM).

### Instalación de Dependencias

1. Clona este repositorio:

   ```bash
   git clone https://github.com/tu-usuario/Herramienta-Ciberseguridad.git
   cd Herramienta-Ciberseguridad
   ```

2. Instala las dependencias necesarias:

    ```bash
    pip install -r requirements.txt
    ```

---

## Uso

Para ejecutar el programa se recomienda crear un entorono virtual de python y ejecutar con privilegios a través del entorno.

```bash
sudo python3 src/main.py
```

---

## Funcionalidades

### Escaneo de Red

El módulo de escaneo de red utiliza Nmap para detectar dispositivos en una red. Permite identificar:

- Dispositivos activos en un rango de IPs.
- Puertos abiertos y servicios en ejecución.
- Sistemas operativos, si es posible (usando el argumento -O de Nmap).

Archivo relacionado: `src/scanner/nmap_scanner.py`

### Fuzzing HTTP

Este módulo realiza fuzzing HTTP en una URL objetivo utilizando palabras predefinidas desde un diccionario. Envía solicitudes para probar:

- Recursos como /admin, /login, etc.
- Rutas sensibles como archivos de configuración.

Los resultados exitosos se muestran en la terminal, y el programa puede manejar excepciones como tiempo de espera o errores de conexión.

Archivo relacionado: `src/fuzzing/fuzzing.py`

### Ataque MITM (Man-in-the-Middle)

El módulo MITM realiza un ataque de suplantación ARP (ARP spoofing), engañando al router y a una víctima para que redirijan su tráfico a través del atacante. Incluye:

- Restauración automática de tablas ARP al finalizar el ataque.
- Redirección de tráfico mediante habilitación de IP forwarding.

Archivo relacionado: `src/mitm/mitm_attack.py`

### Captura de Tráfico

Este módulo permite capturar tráfico de red en tiempo real mientras se realiza el ataque MITM. Guarda los paquetes en un archivo PCAP para su análisis posterior con herramientas como Wireshark.

Archivo relacionado: src/traffic_capture/capture.py

---

## Licencia

Esta herramienta es de código abierto y está bajo la licencia **MIT**.
