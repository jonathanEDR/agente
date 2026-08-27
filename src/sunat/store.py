"""La bóveda: empresas + claves SOL cifradas.

Une dos piezas que se mantienen separadas a propósito:

  - `crypto.Caja` sabe cifrar y descifrar, y no sabe dónde se guarda nada.
  - `repositorios.Repositorio` sabe guardar y leer, y no puede descifrar nada.

Esa separación es lo que permite mover los datos a MongoDB sin debilitar
el modelo de seguridad: el servidor recibe exactamente los mismos bytes
ilegibles que antes guardaba el disco.
"""

from __future__ import annotations

from pathlib import Path

from .crypto import Caja
from .errors import EmpresaNoEncontrada, VaultNoExiste
from .repositorios import Empresa, Repositorio, RepositorioArchivo

__all__ = ["Empresa", "Vault"]


class Vault:
    def __init__(self, repo: Repositorio, caja: Caja) -> None:
        self._repo = repo
        self._caja = caja

    # --- creación / apertura ------------------------------------------------

    @staticmethod
    def existe(repo: Repositorio | Path) -> bool:
        return _como_repo(repo).existe()

    @classmethod
    def crear(cls, repo: Repositorio | Path, password: str) -> "Vault":
        repo = _como_repo(repo)
        caja, params, verificador = Caja.nueva(password)
        repo.crear(params, verificador)
        return cls(repo, caja)

    @classmethod
    def abrir(cls, repo: Repositorio | Path, password: str) -> "Vault":
        repo = _como_repo(repo)
        if not repo.existe():
            raise VaultNoExiste(
                f"No hay bóveda en {repo.describir()}. "
                "Crea una registrando tu primera empresa."
            )
        params, verificador = repo.leer_cabecera()
        return cls(repo, Caja.abrir(password, params, verificador))

    # --- consulta -----------------------------------------------------------

    @property
    def origen(self) -> str:
        return self._repo.describir()

    def listar(self) -> list[Empresa]:
        return sorted(self._repo.listar(), key=lambda e: e.nombre.lower())

    def obtener(self, ruc: str) -> Empresa:
        for e in self._repo.listar():
            if e.ruc == ruc:
                return e
        raise EmpresaNoEncontrada(f"No hay ninguna empresa registrada con RUC {ruc}.")

    # --- modificación -------------------------------------------------------

    def upsert(self, nombre: str, ruc: str, usuario: str, clave: str) -> Empresa:
        empresa = Empresa(
            nombre=nombre,
            ruc=ruc,
            usuario=usuario,
            clave_cifrada=self._caja.cifrar(clave),
        )
        self._repo.guardar(empresa)
        return empresa

    def eliminar(self, ruc: str) -> None:
        self.obtener(ruc)  # valida que exista antes de tocar el repositorio
        self._repo.eliminar(ruc)

    def clave_de(self, empresa: Empresa) -> str:
        return self._caja.descifrar(empresa.clave_cifrada)


def _como_repo(repo: Repositorio | Path) -> Repositorio:
    """Acepta una ruta por comodidad: `Vault.abrir(ruta, password)`."""
    if isinstance(repo, Path):
        return RepositorioArchivo(repo)
    return repo
