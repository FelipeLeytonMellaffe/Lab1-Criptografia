import sys
from scapy.all import *
from datetime import datetime

def obtener_timestamp():
    # Obtener la marca de tiempo actual en formato UTC
    timestamp_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return timestamp_utc

def enviar_paquete_icmp(letra, identificador, secuencia):
    # Construir el paquete ICMP con los campos personalizadosx
    timestamp = obtener_timestamp()
    datos =  bytes(letra + timestamp, 'utf-8')
    relleno = 56 -len(datos)
    datos += bytes(" " * relleno, 'utf-8')
    paquete = IP(dst="127.0.0.1") / ICMP(type=8, code=0, id=identificador, seq=secuencia) / datos
   
    # Enviar el paquete ICMP
    send(paquete, verbose=False)

def main(texto):
    identificador = os.getpid() & 0xFFFF  # Identificador personalizado
    secuencia = 1  # Inicializar el número de secuencia
   
    for caracter in texto:
        enviar_paquete_icmp(caracter, identificador, secuencia)
        print('.\nsent 1 packets.')
        secuencia += 1  # Incrementar el número de secuencia para cada paquete

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error - Introduce el texto a enviar como argumento.")
        print('Ejemplo: python3 programa.py "texto"')
        sys.exit(1)

    texto = sys.argv[1]
    main(texto)