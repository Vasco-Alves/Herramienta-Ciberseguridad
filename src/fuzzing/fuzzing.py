import requests
from colorama import Fore, Style
from urllib.parse import urljoin
from tqdm import tqdm


def load_dictionary(file_path):
    """
    Carga palabras desde un archivo de diccionario.
    :param file_path: Ruta del archivo que contiene las palabras de fuzzing.
    :return: Lista de palabras del diccionario.
    """
    try:
        with open(file_path, "r") as file:
            words = file.read().splitlines()
        print(f"[+] Diccionario cargado con {len(words)} palabras.")
        return words
    except FileNotFoundError:
        print(f"[!] Archivo de diccionario no encontrado: {file_path}")
        return []


def fuzz_http(url, dictionary_path, num_requests=10):
    """
    Realiza fuzzing HTTP en una URL utilizando palabras de un diccionario.

    :param url: La URL objetivo para el fuzzing.
    :param dictionary_path: Ruta al archivo de diccionario.
    :param num_requests: Número máximo de peticiones a enviar.
    """
    words = load_dictionary(dictionary_path)
    if not words:
        print("[!] No se pudo cargar el diccionario.")
        return

    print(f"{Fore.YELLOW}[+] Iniciando fuzzing HTTP en {url} con palabras del diccionario...{Style.RESET_ALL}\n")
    
    with tqdm(total=min(len(words), num_requests), desc="Progreso", unit="url", dynamic_ncols=True) as progress_bar:
        for word in words[:num_requests]:
            full_url = urljoin(url, word)

            try:
                response = requests.get(full_url, timeout=10)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[{response.status_code}] {full_url}{Style.RESET_ALL}")
                    
            except requests.ConnectionError:
                print(f"[!] Error de conexión con la URL: {full_url}")
            except requests.Timeout:
                print(f"[!] Tiempo de espera agotado para la URL: {full_url}")
            except requests.RequestException as e:
                print(f"[!] Error al enviar la petición con la palabra '{word}': {e}")
                
            finally:
                progress_bar.update(1)
                
