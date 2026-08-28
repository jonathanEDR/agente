"""
sunat-launcher — automatiza el ingreso a SUNAT SOL y la lectura de
información del portal.

Regla del proyecto: este paquete SOLO lee. Nunca presenta declaraciones,
nunca modifica datos y nunca envía formularios distintos al de login.
"""

# La version del agente, y la unica fuente de verdad.
#
# pyproject.toml la lee de aqui (`dynamic = ["version"]`), asi que no pueden
# discrepar. Llegaron a decir 0.1.0 y 1.0.0 mientras los tags iban por v1.3.0.
#
# Se publica en /api/handshake y en el globo del icono de bandeja porque no
# saber que version corre cuesta caro: una tarde entera se fue en descubrir
# que el .exe en uso era anterior al arreglo que estabamos probando.
__version__ = "1.4.0"
