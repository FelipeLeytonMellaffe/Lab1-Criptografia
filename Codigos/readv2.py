import sys
from scapy.all import *

def obtener_mensaje_cifrado(pcap_file):
    mensajes = []

    # Leer el archivo pcapng
    paquetes = rdpcap(pcap_file)

    # Obtener los mensajes ICMP transmitidos
    for paquete in paquetes:
        if ICMP in paquete and paquete[ICMP].type == 8:  # Solo paquetes ICMP de tipo echo request
            mensajes.append(paquete.load[0])  # Obtener la primera letra del payload del paquete ICMP

    return mensajes

def descifrar_mensaje(mensaje_cifrado, corrimiento):
    mensaje_descifrado = ""
    if isinstance(mensaje_cifrado, int):  # Verificar si mensaje_cifrado es un entero
        mensaje_cifrado = chr(mensaje_cifrado)  # Convertir a caracter
    for letra in mensaje_cifrado:
        if letra.isalpha():
            codigo = ord(letra)
            codigo_descifrado = (codigo - ord('a') - corrimiento) % 26 + ord('a')
            mensaje_descifrado += chr(codigo_descifrado)
    if not mensaje_descifrado:  # Agregar espacio en blanco si la parte descifrada está vacía
        mensaje_descifrado += " "
    return mensaje_descifrado

def contar_pares_letras(mensaje):
    frecuencia_pares = {'es', 'de', 'la', 'el', 'en', 'te', 'se', 'ra', 'er', 're', 'as', 'le', 'co', 'ie', 'ar', 'an', 'al', 'un', 'no', 'os', 'na', 'do', 'ad', 'to', 'nt', 'lo', 'ra', 'on', 'ta', 'ha', 'or', 'el', 'la', 'me', 'en', 'ue', 'si', 'lo', 'ha', 'lo', 'po', 'ma', 'da', 'di', 'ic', 'io', 'do', 'nt', 'ro', 'un', 'sa', 'ch', 'ac', 'am', 'ra', 'da', 'nc', 'al', 'le', 're', 'al', 'so', 'ta', 'os', 'to', 'si', 'da', 'ti', 'an', 'mo', 'ic', 'pa', 'el', 'om', 'la', 'te', 'ne', 'ci', 'se', 'lo', 'un', 'no', 'va', 'pa', 'st', 'id', 'pe', 'ar', 'ca', 'na', 'ar', 'ta', 'no', 'de', 'ma', 'qu', 'ue', 'er', 'a ', 'en', 'el', 'lo', 'su', 'el', 'ti', 'on', 'st', 'ro', 'co', 'ci', 'al', 'pe', 'ta', 'tr', 'e ', 'lo', 'en', 'er', 'qu', 'ia', 'po', 'qu', 'un', 're', 'ad', 'do', 'mo', 'ra', 'ce', 'os', 'la', 'ic', 'ci', 'or', 'sa', 'un', 'la', 'da', 'si', 'mi', 'el', 'do', 'ue', 'da', 'qu', 'so', 'se', 'ho', 'di', 'an', 'so', 'to', 'to', 'os', 'so', 'om', 'un', 'en', 'te', 'vi', 'ad', 'lo', 'se', 'de', 'la', 'ar', 'ar', 'sa', 'ce', 'an', 'to', 'do', 're', 'al', 'es', 'di', 'de', 'sa', 'al', 'id', 'ti', 'es', 'ma', 'en', 'na', 'se', 'on', 'un', 'al', 'di', 'co', 'le', 'lo', 'un', 'co', 'qu', 'la', 'so', 'ma', 'pa', 'ta', 'tu', 'ic', 'or', 'no', 'la', 'tu', 'di', 'ni', 'ra', 'ci', 'co', 'ra', 'al', 'en', 'ar', 'an', 'ra', 'li', 'ar', 'qu', 'de', 'de', 'te', 'el', 'de', 'do', 'vi', 'an', 'ti', 'me', 'as', 'un', 'en', 'ic', 'do', 'la', 'el', 'no', 'de', 'te', 'na', 'to', 'el', 'de', 'lo', 'ci', 'ad', 'er', 'os', 'de', 're', 'se', 'la', 'el', 'os', 'ha', 'le', 'ro', 'an', 'na', 'ta', 'de', 'se', 'po', 'sa', 'su', 'no', 'te', 'si', 'si', 'ha', 'na', 'st', 'ic', 'su', 'se', 've', 'pr', 'so', 'en', 'al', 'di', 'ho', 'pe', 'so', 'an', 'en', 'de', 'co', 'el', 'un', 'to', 'co', 'st', 'al', 'su', 'la', 'te', 'mo', 'de', 'mi', 'en', 'in', 'lo', 've', 'so', 'ra', 'ha', 'ar', 'le', 'se', 'ha', 'to', 're', 'da', 'to', 'el', 'di', 'tr', 'de', 'ra', 'os', 'ta', 'co', 'ho', 'si', 'ra', 'en', 'qu', 'lo', 'mi', 'ha', 'ci', 'le', 'tr', 'sa', 'le', 'ta', 'an', 'ce', 'de', 'de', 'de', 're', 'de', 'es', 'al', 'so', 'le', 'el', 'an', 'de', 'en', 'te', 'el', 'al', 'ta', 've', 'ha', 'ta', 'de', 'le', 'lo', 'sa', 'os', 'en', 'ma', 'al', 'es', 'el', 'de', 'de', 'pr', 'ci', 'pe', 'te', 'el', 've', 'ha', 're', 'ho', 'de', 'as', 'po', 'en', 'ci', 'do', 'an', 'pe', 'as', 'un', 'ta', 'pe', 'ar', 'un', 'di', 'no', 'ad', 'in', 'ta', 'so', 'er', 'ho', 'pa', 'se', 'la', 'pa', 'se', 'mi', 'se', 'la'}
    cantidad_pares = 0
    for i in range(len(mensaje) - 1):
        par = mensaje[i:i+2].lower()
        if par in frecuencia_pares:
            cantidad_pares += 1
    return cantidad_pares

def main(pcap_file):
    mensajes_cifrados = obtener_mensaje_cifrado(pcap_file)
    pares_max = 0
    mensaje_descifrado_max = ""
    mensajes = []

    # Generar todas las combinaciones posibles de corrimiento y descifrar el mensaje para cada una
    for corrimiento in range(26):
        mensaje_descifrado = ""
        for mensaje_cifrado in mensajes_cifrados:
            parte_descifrada = descifrar_mensaje(mensaje_cifrado, corrimiento)
            if parte_descifrada:  # Verificar si la parte descifrada no está vacía
                mensaje_descifrado += parte_descifrada[0]  # Tomar solo la primera letra
        cant_pares = contar_pares_letras(mensaje_descifrado)  # Contar pares de letras
        if cant_pares > pares_max:
            pares_max = cant_pares
            mensaje_descifrado_max = mensaje_descifrado

        mensajes.append(mensaje_descifrado)

    # Imprimir mensajes
    for i in range(len(mensajes)):
        if mensajes[i] == mensaje_descifrado_max:
            print(f"\033[92m{i} {mensaje_descifrado_max}\033[0m")
        else:
            print(i, mensajes[i])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error - Introduce el archivo pcapng como argumento.")
        print('Ejemplo: sudo python3 readv2.py cesar.pcapng')
        sys.exit(1)

    pcap_file = sys.argv[1]
    main(pcap_file)