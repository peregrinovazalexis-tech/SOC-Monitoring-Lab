
from pathlib import Path
from collections import Counter
import re


def analizar_registros(ruta_archivo):

    intentos_fallidos = 0
    accesos_exitosos = 0
    usuarios_invalidos = 0

    with open(ruta_archivo, "r", encoding="utf-8-sig") as archivo:
        for linea in archivo:

            if "Failed password" in linea:
                intentos_fallidos += 1

            elif "Accepted password" in linea:
                accesos_exitosos += 1

            elif "Invalid user" in linea:
                usuarios_invalidos += 1

    return {
        "intentos_fallidos": intentos_fallidos,
        "accesos_exitosos": accesos_exitosos,
        "usuarios_invalidos": usuarios_invalidos
    }



def contar_ips(ruta_archivo):

    patron_ip = re.compile(
        r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    )

    contador_ips = {}

    with open(ruta_archivo, "r", encoding="utf-8-sig") as archivo:
        for linea in archivo:
            ips_encontradas = patron_ip.findall(linea)
            for ip in ips_encontradas:
                # 1. Inicializar la IP si todavía no existe
                if ip not in contador_ips:
                    contador_ips[ip] = {
                        "fallidos": 0,
                        "exitosos": 0,
                        "usuarios_invalidos": 0
                    }
                # 2. Clasificar el evento
                if "Failed password" in linea:
                    contador_ips[ip]["fallidos"] += 1
                elif "Accepted password" in linea:
                    contador_ips[ip]["exitosos"] += 1
                elif "Invalid user" in linea:
                    contador_ips[ip]["usuarios_invalidos"] += 1

    return contador_ips

def detectar_amenazas(datos):
    alertas=[]
    if datos["intentos_fallidos"] >= 5:
        alertas.append("Alerta: Múltiples intentos fallidos de inicio de sesión detectados.")
    return alertas

BASE_DIR = Path(__file__).resolve().parent.parent
ruta = BASE_DIR / "data" / "auth.log"

resultado = analizar_registros(ruta)
ips_encontradas = contar_ips(ruta)
datos = analizar_registros(ruta)
alertas = detectar_amenazas(datos)

print("\nREPORTE DE SEGURIDAD")
print("--------------------")

print("\nEventos:")
for evento, cantidad in resultado.items():
    print(f"{evento}: {cantidad}")

print("\nEventos por dirección IP:")
for ip, cantidad in ips_encontradas.items():
    print(f"IP: {ip} | Eventos: {cantidad}")

print("\nAlertas:")
for alerta in alertas:
    print(alerta)
