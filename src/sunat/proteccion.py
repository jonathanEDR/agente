"""Protección de secretos locales con DPAPI de Windows.

El token de dispositivo se guardaba en `device.json` en texto plano. El
`chmod(0o600)` que hay al escribirlo no hace nada en Windows —el propio
comentario lo dice—, así que cualquier programa que corriera con la sesión
del usuario podía leerlo: un instalador con sorpresa, una extensión de
Chrome, un adjunto abierto sin pensar. Y con ese token se piden al backend
la cabecera de la bóveda y todas las claves cifradas, que es exactamente el
material para atacar la contraseña maestra sin conexión y sin límite de
intentos.

DPAPI cierra eso sin pedirle nada al usuario ni guardar ninguna llave: el
sistema deriva una a partir de las credenciales de la cuenta de Windows. El
archivo copiado a otra máquina, o leído por otro usuario del mismo equipo,
ya no se puede descifrar.

Lo que NO resuelve, y conviene tener claro: un programa corriendo como este
mismo usuario puede llamar a `CryptUnprotectData` igual que nosotros. Contra
eso no hay defensa desde aquí —tendría que ser el sistema operativo—, pero
sube el listón de "leer un archivo de texto" a "ejecutar código en esta
sesión", y deja sin valor las copias del archivo suelto: respaldos, carpetas
sincronizadas, discos robados.
"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes

from .errors import SunatError

# Prefijo que distingue un valor protegido de uno en claro. Sin él no se
# podría leer lo que ya está guardado sin protección.
MARCA = "dpapi1:"

# Entropía fija de la aplicación.
#
# No es un secreto: va dentro del ejecutable. Lo que hace es atar el blob a
# este programa, de modo que un blob DPAPI producido por otra aplicación del
# mismo usuario no se pueda colar dentro de device.json.
_ENTROPIA = b"sunat-launcher/device-token/v1"

# Sin esto, DPAPI puede intentar mostrar interfaz. El agente corre sin
# consola y a veces sin escritorio interactivo: mejor que falle a que cuelgue.
_UI_PROHIBIDA = 0x01


class ProteccionNoDisponible(SunatError):
    """El sistema no ofrece DPAPI (no es Windows)."""


class ProteccionFallida(SunatError):
    """DPAPI existe pero no pudo descifrar este dato."""


class _Blob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def disponible() -> bool:
    """Si este sistema tiene DPAPI. Falso en Linux y macOS."""
    return hasattr(ctypes, "windll")


def _apis():
    """crypt32 y kernel32 con las firmas declaradas.

    Declarar `argtypes` no es decorativo en 64 bits: sin ellas ctypes trunca
    los punteros a 32 bits y la llamada falla de formas que no se parecen a
    su causa.
    """
    if not disponible():
        raise ProteccionNoDisponible("DPAPI solo existe en Windows.")

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    firma = [
        ctypes.POINTER(_Blob),  # datos de entrada
        wintypes.LPCWSTR,  # descripción
        ctypes.POINTER(_Blob),  # entropía
        ctypes.c_void_p,  # reservado
        ctypes.c_void_p,  # estructura de prompt
        wintypes.DWORD,  # banderas
        ctypes.POINTER(_Blob),  # salida
    ]

    for fn in (crypt32.CryptProtectData, crypt32.CryptUnprotectData):
        fn.argtypes = firma
        fn.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    return crypt32, kernel32


def _llamar(fn, kernel32, datos: bytes) -> bytes:
    """Ejecuta CryptProtectData o CryptUnprotectData sobre `datos`.

    Los buffers de entrada se mantienen vivos en variables locales a
    propósito: si solo existieran dentro de la estructura, el recolector de
    Python podría liberarlos antes de que la llamada al sistema los use.
    """
    buf_datos = ctypes.create_string_buffer(datos, len(datos))
    buf_entropia = ctypes.create_string_buffer(_ENTROPIA, len(_ENTROPIA))

    entrada = _Blob(
        len(datos), ctypes.cast(buf_datos, ctypes.POINTER(ctypes.c_char))
    )
    entropia = _Blob(
        len(_ENTROPIA), ctypes.cast(buf_entropia, ctypes.POINTER(ctypes.c_char))
    )
    salida = _Blob()

    ok = fn(
        ctypes.byref(entrada),
        None,
        ctypes.byref(entropia),
        None,
        None,
        _UI_PROHIBIDA,
        ctypes.byref(salida),
    )

    if not ok:
        raise ProteccionFallida(
            f"DPAPI rechazó la operación (error {ctypes.get_last_error()})."
        )

    try:
        return ctypes.string_at(salida.pbData, salida.cbData)
    finally:
        kernel32.LocalFree(salida.pbData)


def proteger(texto: str) -> str:
    """Devuelve el texto cifrado para este usuario de Windows, con su marca.

    Fuera de Windows devuelve el texto tal cual. Es deliberado: el agente es
    de Windows, y hacer fallar el guardado en Linux solo rompería el
    desarrollo y los tests sin proteger a nadie.
    """
    if not disponible():
        return texto

    crypt32, kernel32 = _apis()
    cifrado = _llamar(crypt32.CryptProtectData, kernel32, texto.encode("utf-8"))
    return MARCA + base64.b64encode(cifrado).decode("ascii")


def esta_protegido(valor: str) -> bool:
    return valor.startswith(MARCA)


def desproteger(valor: str) -> str:
    """Recupera un valor protegido. Devuelve tal cual lo que no lo esté.

    Que un valor sin marca pase sin tocar es lo que permite leer los
    `device.json` que se escribieron antes de que esto existiera.
    """
    if not esta_protegido(valor):
        return valor

    if not disponible():
        raise ProteccionNoDisponible(
            "Este dato fue protegido con DPAPI de Windows y no se puede leer "
            "en este sistema."
        )

    try:
        crudo = base64.b64decode(valor[len(MARCA) :], validate=True)
    except (ValueError, base64.binascii.Error) as e:
        raise ProteccionFallida(f"El dato protegido está corrupto ({e}).") from e

    crypt32, kernel32 = _apis()
    return _llamar(crypt32.CryptUnprotectData, kernel32, crudo).decode("utf-8")
