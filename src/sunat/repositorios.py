"""Dónde se guardan las empresas: archivo local o MongoDB (vía la API).

Los dos repositorios guardan exactamente lo mismo: metadatos en claro
(nombre, RUC, usuario) y la clave SOL **ya cifrada**. Ninguno conoce la
contraseña maestra ni puede descifrar nada — eso vive en `crypto.Caja`.

Por eso cambiar de archivo a Mongo no cambia el modelo de seguridad: el
servidor recibe los mismos bytes ilegibles que hoy guarda tu disco.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .crypto import ParametrosKDF
from .errors import SunatError, VaultCorrupto, VaultNoExiste

VERSION_BOVEDA = 1


@dataclass(frozen=True)
class Empresa:
    nombre: str
    ruc: str
    usuario: str
    clave_cifrada: str

    def a_dict(self) -> dict[str, str]:
        return {
            "nombre": self.nombre,
            "ruc": self.ruc,
            "usuario": self.usuario,
            "clave_cifrada": self.clave_cifrada,
        }

    @staticmethod
    def desde_dict(d: dict[str, Any]) -> "Empresa":
        try:
            return Empresa(
                nombre=str(d["nombre"]),
                ruc=str(d["ruc"]),
                usuario=str(d["usuario"]),
                clave_cifrada=str(d["clave_cifrada"]),
            )
        except KeyError as e:
            raise VaultCorrupto(f"Empresa sin el campo {e}.") from e


class Repositorio(Protocol):
    """Contrato que cumplen tanto el archivo como MongoDB."""

    def existe(self) -> bool: ...

    def crear(self, params: ParametrosKDF, verificador: str) -> None: ...

    def leer_cabecera(self) -> tuple[ParametrosKDF, str]:
        """Devuelve (parámetros de derivación, verificador)."""
        ...

    def listar(self) -> list[Empresa]: ...

    def guardar(self, empresa: Empresa) -> None: ...

    def eliminar(self, ruc: str) -> None: ...

    def describir(self) -> str:
        """Texto corto para mostrarle al usuario dónde están sus datos."""
        ...


# --- archivo local ----------------------------------------------------------


class RepositorioArchivo:
    """El vault.json de siempre. Escritura atómica: un corte a medias no
    debe dejar el archivo truncado, porque perderlo significa volver a
    registrar todas las empresas."""

    def __init__(self, ruta: Path) -> None:
        self.ruta = ruta

    def describir(self) -> str:
        return f"archivo local ({self.ruta})"

    def existe(self) -> bool:
        return self.ruta.exists()

    def _leer(self) -> dict[str, Any]:
        if not self.ruta.exists():
            raise VaultNoExiste(f"No hay bóveda en {self.ruta}.")
        try:
            datos = json.loads(self.ruta.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            raise VaultCorrupto(f"No se pudo leer la bóveda ({e}).") from e
        if datos.get("version") != VERSION_BOVEDA:
            raise VaultCorrupto(
                f"Versión de bóveda no soportada: {datos.get('version')!r}."
            )
        return datos

    def _escribir(self, datos: dict[str, Any]) -> None:
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.ruta.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        os.replace(tmp, self.ruta)
        try:
            os.chmod(self.ruta, 0o600)  # efectivo en Unix; inocuo en Windows
        except OSError:
            pass

    def crear(self, params: ParametrosKDF, verificador: str) -> None:
        self._escribir(
            {
                "version": VERSION_BOVEDA,
                "kdf": params.a_dict(),
                "check": verificador,
                "empresas": [],
            }
        )

    def leer_cabecera(self) -> tuple[ParametrosKDF, str]:
        datos = self._leer()
        try:
            return ParametrosKDF.desde_dict(datos["kdf"]), str(datos["check"])
        except KeyError as e:
            raise VaultCorrupto(f"Bóveda sin el campo {e}.") from e

    def listar(self) -> list[Empresa]:
        return [Empresa.desde_dict(d) for d in self._leer().get("empresas", [])]

    def guardar(self, empresa: Empresa) -> None:
        datos = self._leer()
        otras = [e for e in datos.get("empresas", []) if e.get("ruc") != empresa.ruc]
        datos["empresas"] = otras + [empresa.a_dict()]
        self._escribir(datos)

    def eliminar(self, ruc: str) -> None:
        datos = self._leer()
        datos["empresas"] = [
            e for e in datos.get("empresas", []) if e.get("ruc") != ruc
        ]
        self._escribir(datos)


# --- MongoDB, a través de la API ---------------------------------------------


class ErrorApi(SunatError):
    """La API no respondió o respondió con error."""


class TokenRechazado(ErrorApi):
    """El backend no reconoce el token de esta computadora.

    Va aparte del resto de errores de API porque el usuario tiene que hacer
    algo distinto: no es "el backend está caído, espera", es "este equipo fue
    revocado, vuelve a vincularlo". Sin distinguirlo, la interfaz manda a
    esperar a alguien que va a esperar para siempre.
    """


class RepositorioApi:
    """Habla con el backend que guarda en MongoDB.

    Se usa `urllib` de la biblioteca estándar a propósito: el agente no
    necesita arrastrar `requests` por cuatro llamadas HTTP.

    Lo que viaja por la red es siempre la clave YA cifrada. El servidor no
    tiene forma de leerla.

    El token identifica a ESTA computadora y, a través de ella, al usuario
    dueño de los datos. El backend saca de él a quién pertenece cada bóveda:
    ninguna ruta acepta un id de usuario por parámetro, porque eso dejaría
    leer las bóvedas ajenas con solo cambiar un número.
    """

    # El backend versiona su API. Fijar el prefijo aquí, en un solo sitio,
    # evita que una v2 rompa a los agentes viejos en silencio.
    PREFIJO = "/api/v1"

    def __init__(self, base_url: str, token: str = "", timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def describir(self) -> str:
        return f"MongoDB vía {self.base_url}"

    # --- transporte ---------------------------------------------------------

    def _pedir(self, metodo: str, ruta: str, cuerpo: dict | None = None) -> Any:
        import urllib.error
        import urllib.request

        url = f"{self.base_url}{self.PREFIJO}{ruta}"
        datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
        peticion = urllib.request.Request(url, data=datos, method=metodo)
        peticion.add_header("Content-Type", "application/json")
        if self.token:
            peticion.add_header("Authorization", f"Bearer {self.token}")

        try:
            with urllib.request.urlopen(peticion, timeout=self.timeout) as r:
                crudo = r.read().decode("utf-8")
                return json.loads(crudo) if crudo else None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            detalle = ""
            try:
                detalle = json.loads(e.read().decode("utf-8")).get("error", "")
            except Exception:  # noqa: BLE001 - el cuerpo del error es opcional
                pass
            if e.code in (401, 403):
                raise TokenRechazado(
                    "El backend rechazó el token de esta computadora. Puede "
                    "haber sido revocado desde el panel: vuelve a vincularla."
                ) from e
            raise ErrorApi(f"La API respondió {e.code}. {detalle}".strip()) from e
        except urllib.error.URLError as e:
            raise ErrorApi(
                f"No se pudo conectar con la API en {self.base_url} ({e.reason}). "
                "¿Está corriendo el backend?"
            ) from e

    # --- contrato -----------------------------------------------------------

    def existe(self) -> bool:
        return self._pedir("GET", "/vault") is not None

    def crear(self, params: ParametrosKDF, verificador: str) -> None:
        self._pedir(
            "POST", "/vault", {"kdf": params.a_dict(), "check": verificador}
        )

    def leer_cabecera(self) -> tuple[ParametrosKDF, str]:
        datos = self._pedir("GET", "/vault")
        if datos is None:
            raise VaultNoExiste("Todavía no hay una bóveda creada en el servidor.")
        try:
            return ParametrosKDF.desde_dict(datos["kdf"]), str(datos["check"])
        except KeyError as e:
            raise VaultCorrupto(f"La API devolvió una bóveda sin el campo {e}.") from e

    def listar(self) -> list[Empresa]:
        datos = self._pedir("GET", "/companies") or []
        return [Empresa.desde_dict(d) for d in datos]

    def guardar(self, empresa: Empresa) -> None:
        self._pedir("PUT", f"/companies/{empresa.ruc}", empresa.a_dict())

    def eliminar(self, ruc: str) -> None:
        self._pedir("DELETE", f"/companies/{ruc}")
