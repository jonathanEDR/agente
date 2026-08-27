"""Vinculación del agente con una cuenta del SaaS.

Antes, cuando el launcher era de una sola persona, el agente hablaba con el
backend usando una `SUNAT_API_KEY` puesta a mano en un `.env`. Eso no sirve
en un SaaS: sería una única llave compartida por todos los usuarios, y quien
la tuviera podría leer la bóveda de cualquiera.

Ahora cada computadora recibe su propio token, emitido por el backend para
un usuario concreto y revocable desde el panel sin tocar las demás.

Lo que se guarda aquí NO es secreto en el sentido de las claves SOL: el
token da acceso a *texto cifrado*, que sin la contraseña maestra no sirve
de nada. Aun así vive en la carpeta de datos del usuario y no en el
proyecto, por lo mismo que el vault: para que no acabe en un repositorio
por un `.gitignore` incompleto.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

from . import proteccion
from .errors import SunatError
from .log import obtener

_log = obtener("vinculacion")

if TYPE_CHECKING:
    from .config import Config

NOMBRE_ARCHIVO = "device.json"
VERSION = 1


class VinculacionInvalida(SunatError):
    """Los datos de vinculación no sirven."""


@dataclass(frozen=True)
class Vinculacion:
    """A qué backend hablar y con qué token."""

    token: str
    api_url: str

    def describir(self) -> str:
        return f"cuenta vinculada en {self.api_url}"


def ruta(cfg: "Config") -> Path:
    return cfg.data_dir / NOMBRE_ARCHIVO


def _origen(url: str) -> str:
    """Reduce una URL a esquema://host[:puerto], o falla si no es una.

    Se compara el origen reconstruido y no la cadena que llegó, porque son
    cosas distintas: `https://backend-real.com@evil.com` tiene como host a
    `evil.com`, y cualquier comparación de texto sobre la cadena original lo
    daría por bueno.
    """
    from urllib.parse import urlparse

    partes = urlparse((url or "").strip())

    if partes.scheme not in {"http", "https"}:
        raise VinculacionInvalida(
            f"Esquema no soportado: {partes.scheme!r}. Tiene que ser https."
        )

    if not partes.hostname:
        raise VinculacionInvalida("La URL del backend no tiene host.")

    if partes.path.strip("/"):
        raise VinculacionInvalida(
            f"La URL del backend no lleva ruta: sobra {partes.path!r}. "
            "El agente le agrega /api/v1 por su cuenta."
        )

    origen = f"{partes.scheme}://{partes.hostname}"
    return f"{origen}:{partes.port}" if partes.port else origen


def validar_api_url(api_url: str, permitidos: Sequence[str]) -> str:
    """Comprueba que la URL sea un destino aceptable para el token.

    Dos filtros, y el segundo es el que importa.

    HTTPS salvo en localhost evita que el token viaje a la vista. Pero eso no
    dice NADA sobre a quién se le está entregando: durante un tiempo esta
    función aceptaba cualquier `https://` del mundo, así que bastaba un POST
    desde un origen ya permitido —o un script inyectado en el panel— para
    apuntar el agente a un servidor del atacante. A partir de ahí el usuario
    desbloquea contra una bóveda ajena y cada clave que guarda después se
    escribe en la máquina de otro.

    La lista blanca es lo que cierra eso. Vive en config.py, horneada en el
    ejecutable, porque una lista que se puede ampliar desde la web no protege
    de nada.
    """
    if not (api_url or "").strip():
        raise VinculacionInvalida("Falta la URL del backend.")

    origen = _origen(api_url)

    from urllib.parse import urlparse

    es_local = (urlparse(origen).hostname or "") in {"127.0.0.1", "localhost", "::1"}
    if origen.startswith("http://") and not es_local:
        raise VinculacionInvalida(
            "El backend tiene que ser HTTPS, salvo en localhost durante el "
            "desarrollo. Con HTTP plano el token viajaría a la vista."
        )

    # Los permitidos se normalizan igual que la entrada: si la lista trae una
    # barra final o mayúsculas, tiene que seguir coincidiendo.
    conocidos = {_origen(p) for p in permitidos if (p or "").strip()}

    if origen not in conocidos:
        raise VinculacionInvalida(
            f"Este agente no se vincula a {origen}. "
            "Solo acepta el backend del producto, y la lista va compilada "
            "dentro del programa: si de verdad cambió, hay que publicar una "
            "versión nueva del agente."
        )

    return origen


def leer(cfg: "Config") -> Vinculacion | None:
    """La vinculación guardada, o None si esta computadora no está vinculada."""
    archivo = ruta(cfg)
    if not archivo.is_file():
        return None

    try:
        datos = json.loads(archivo.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Un archivo ilegible se trata como "no vinculado": el usuario puede
        # volver a vincular desde el panel, que es más útil que un error.
        return None

    guardado = str(datos.get("token") or "")
    api_url = str(datos.get("api_url") or "")
    if not guardado or not api_url:
        return None

    try:
        token = proteccion.desproteger(guardado)
    except SunatError as e:
        # DPAPI ata el dato a esta cuenta de Windows y a esta máquina. Que
        # falle casi siempre significa que el archivo llegó de otro lado: una
        # copia de seguridad restaurada, una carpeta sincronizada, un perfil
        # migrado. Se trata como "no vinculado" —el usuario vuelve a vincular
        # desde el panel en dos clics— y no como un error que lo deje sin
        # saber qué hacer.
        _log.warning(
            "No se pudo leer el token de %s (%s). Esta computadora queda como "
            "no vinculada; vuelve a vincularla desde el panel.",
            archivo,
            e,
        )
        return None

    return Vinculacion(token=token, api_url=api_url.rstrip("/"))


def proteger_en_disco(cfg: "Config") -> bool:
    """Reescribe un `device.json` en texto plano dejándolo protegido.

    Corre al arrancar el agente, una sola vez por instalación. Va aparte de
    `leer` a propósito: `leer` se llama en cada petición y una función de
    lectura que escribe en disco como efecto secundario es la clase de cosa
    que después nadie encuentra.

    Devuelve si hubo algo que migrar.
    """
    archivo = ruta(cfg)
    if not archivo.is_file() or not proteccion.disponible():
        return False

    try:
        datos = json.loads(archivo.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False

    token = str(datos.get("token") or "")
    if not token or proteccion.esta_protegido(token):
        return False

    datos["token"] = proteccion.proteger(token)
    _escribir(archivo, datos)
    _log.info("El token de esta computadora quedó protegido con DPAPI.")
    return True


def guardar(cfg: "Config", token: str, api_url: str) -> Vinculacion:
    token = (token or "").strip()
    if not token:
        raise VinculacionInvalida("Falta el token del dispositivo.")

    url = validar_api_url(api_url, cfg.backends_permitidos())
    archivo = ruta(cfg)

    _escribir(
        archivo,
        {
            "version": VERSION,
            # Cifrado con las credenciales de esta cuenta de Windows. El
            # archivo copiado a otra máquina ya no sirve.
            "token": proteccion.proteger(token),
            "api_url": url,
        },
    )

    return Vinculacion(token=token, api_url=url)


def _escribir(archivo: Path, datos: dict) -> None:
    """Escritura atómica, igual que el vault.

    Un corte a medias no debe dejar un archivo truncado que luego se lea como
    "no vinculado" — o peor, como un token a medias.
    """
    archivo.parent.mkdir(parents=True, exist_ok=True)

    tmp = archivo.with_suffix(".tmp")
    tmp.write_text(json.dumps(datos, indent=2), encoding="utf-8")
    os.replace(tmp, archivo)
    try:
        archivo.chmod(0o600)  # efectivo en Unix; inocuo en Windows
    except OSError:
        pass


def olvidar(cfg: "Config") -> bool:
    """Desvincula esta computadora. Devuelve si había algo que borrar.

    Solo borra el apuntador local: el dispositivo sigue existiendo en el
    backend hasta que se revoque desde el panel. Son dos operaciones porque
    resuelven casos distintos —"ya no uso esta PC" y "me robaron esa PC"— y
    la segunda tiene que poder hacerse sin tener la máquina delante.
    """
    archivo = ruta(cfg)
    if not archivo.is_file():
        return False
    archivo.unlink()
    return True
