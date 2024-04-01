import sys

def cesar(texto, corrimiento):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            codigo = ord(caracter)
            if caracter.islower():
                codigo_cifrado = (codigo - ord('a') + corrimiento) % 26 + ord('a')
            elif caracter.isupper():
                codigo_cifrado = (codigo - ord('A') + corrimiento) % 26 + ord('A')
            texto_cifrado += chr(codigo_cifrado)
        else:
            texto_cifrado += caracter
    return texto_cifrado




if len(sys.argv) == 3:
    texto = sys.argv[1]
    corrimiento = int(sys.argv[2])
else:
    print("Error - Introduce los argumentos correctamente")
    print('Ejemplo: python3 cesar.py "criptografia y seguridad en redes" 9')

texto_cifrado = cesar(texto, corrimiento)
print(texto_cifrado)