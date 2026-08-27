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
from typing import TYPE_CHECKING

from .errors import SunatError

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


def validar_api_url(api_url: str) -> str:
    """Comprueba que la URL sea un destino aceptable para el token.

    Se exige HTTPS salvo en localhost. Sin esto, una página del origen
    permitido podría vincular el agente contra un servidor suyo en la red
    local por HTTP plano y quedarse con el tráfico.
    """
    url = (api_url or "").strip().rstrip("/")
    if not url:
        raise VinculacionInvalida("Falta la URL del backend.")

    from urllib.parse import urlparse

    partes = urlparse(url)
    if partes.scheme not in {"http", "https"}:
        raise VinculacionInvalida(f"Esquema no soportado: {partes.scheme!r}.")

    es_local = (partes.hostname or "") in {"127.0.0.1", "localhost", "::1"}
    if partes.scheme == "http" and not es_local:
        raise VinculacionInvalida(
            "El backend tiene que ser HTTPS, salvo en localhost durante el "
            "desarrollo. Con HTTP plano el token viajaría a la vista."
        )
    return url


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

    token = str(datos.get("token") or "")
    api_url = str(datos.get("api_url") or "")
    if not token or not api_url:
        return None

    return Vinculacion(token=token, api_url=api_url.rstrip("/"))


def guardar(cfg: "Config", token: str, api_url: str) -> Vinculacion:
    token = (token or "").strip()
    if not token:
        raise VinculacionInvalida("Falta el token del dispositivo.")

    url = validar_api_url(api_url)
    archivo = ruta(cfg)
    archivo.parent.mkdir(parents=True, exist_ok=True)

    # Escritura atómica, igual que el vault: un corte a medias no debe dejar
    # un archivo truncado que luego se lea como "no vinculado".
    tmp = archivo.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"version": VERSION, "token": token, "api_url": url}, indent=2),
        encoding="utf-8",
    )
    os.replace(tmp, archivo)
    try:
        archivo.chmod(0o600)  # efectivo en Unix; inocuo en Windows
    except OSError:
        pass

    return Vinculacion(token=token, api_url=url)


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
