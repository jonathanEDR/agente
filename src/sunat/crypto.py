"""Cifrado de las claves SOL a partir de una contraseña maestra.

Modelo: *zero-knowledge*. La llave se deriva con scrypt de una contraseña
que solo existe en tu cabeza y en la memoria del proceso; nunca se escribe
en disco ni se manda a ningún servidor. Lo que se guarda —en un archivo o
en MongoDB— es texto cifrado que el almacenamiento no puede leer.

Consecuencia deliberada: si un día te roban la base de datos, no se llevan
nada usable. La otra cara es que si pierdes la contraseña maestra, nadie
puede recuperar las claves — ni tú.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .errors import ClaveMaestraInvalida, PasswordDebil, VaultCorrupto

# Parámetros scrypt. Se guardan junto a los datos para que cambiarlos en el
# futuro no invalide las bóvedas ya creadas.
SCRYPT_N = 2**15  # ~32 MB de memoria
SCRYPT_R = 8
SCRYPT_P = 1
LONGITUD_LLAVE = 32
LONGITUD_SALT = 16

# Texto que se cifra al crear la bóveda; descifrarlo con éxito prueba que la
# contraseña maestra es correcta, sin tocar ninguna clave SOL.
TEXTO_VERIFICACION = b"sunat-launcher-vault-v1"

# Longitud mínima al CREAR una bóveda. No se aplica al abrirla: una bóveda
# vieja puede tener cualquier contraseña y bloquearla dejaría sus datos
# inaccesibles.
#
# Existe porque una bóveda es irrecuperable por diseño: crear una con dos
# letras tecleadas por accidente entierra los datos para siempre, y eso ya
# pasó una vez durante las pruebas.
MINIMO_PASSWORD = 8


def validar_password_nueva(password: str) -> None:
    if len(password) < MINIMO_PASSWORD:
        raise PasswordDebil(
            f"La contraseña maestra debe tener al menos {MINIMO_PASSWORD} "
            "caracteres. No se puede recuperar si la pierdes, así que "
            "conviene que sea una que recuerdes y no un tecleo suelto."
        )


@dataclass(frozen=True)
class ParametrosKDF:
    """Cómo derivar la llave. Viaja junto a los datos cifrados.

    El salt tiene que estar donde estén los datos: sin él no se puede
    reconstruir la misma llave desde otra computadora.
    """

    salt: bytes
    n: int = SCRYPT_N
    r: int = SCRYPT_R
    p: int = SCRYPT_P

    @staticmethod
    def nuevos() -> "ParametrosKDF":
        return ParametrosKDF(salt=os.urandom(LONGITUD_SALT))

    def a_dict(self) -> dict[str, Any]:
        return {
            "algo": "scrypt",
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "n": self.n,
            "r": self.r,
            "p": self.p,
        }

    @staticmethod
    def desde_dict(d: dict[str, Any]) -> "ParametrosKDF":
        try:
            return ParametrosKDF(
                salt=base64.b64decode(d["salt"]),
                n=int(d["n"]),
                r=int(d["r"]),
                p=int(d["p"]),
            )
        except (KeyError, TypeError, ValueError, base64.binascii.Error) as e:
            raise VaultCorrupto(f"Parámetros de cifrado ilegibles ({e}).") from e


def derivar_llave(password: str, params: ParametrosKDF) -> bytes:
    """Devuelve una llave lista para Fernet (base64 urlsafe de 32 bytes)."""
    # Import local: scrypt es lo más caro de importar de todo cryptography.
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(
        salt=params.salt, length=LONGITUD_LLAVE, n=params.n, r=params.r, p=params.p
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


class Caja:
    """Cifra y descifra con la llave derivada. No sabe nada de almacenamiento."""

    def __init__(self, fernet: Fernet) -> None:
        self._fernet = fernet

    # --- construcción -------------------------------------------------------

    @classmethod
    def nueva(cls, password: str) -> tuple["Caja", ParametrosKDF, str]:
        """Crea una caja nueva. Devuelve también qué hay que persistir."""
        validar_password_nueva(password)
        params = ParametrosKDF.nuevos()
        caja = cls(Fernet(derivar_llave(password, params)))
        return caja, params, caja.cifrar(TEXTO_VERIFICACION.decode("ascii"))

    @classmethod
    def abrir(cls, password: str, params: ParametrosKDF, verificador: str) -> "Caja":
        """Reabre una caja existente. Falla si la contraseña no es la correcta."""
        caja = cls(Fernet(derivar_llave(password, params)))
        if not caja._verifica(verificador):
            raise ClaveMaestraInvalida("Contraseña maestra incorrecta.")
        return caja

    def _verifica(self, verificador: str) -> bool:
        try:
            return self.descifrar(verificador) == TEXTO_VERIFICACION.decode("ascii")
        except VaultCorrupto:
            return False

    # --- uso ----------------------------------------------------------------

    def cifrar(self, texto: str) -> str:
        return self._fernet.encrypt(texto.encode("utf-8")).decode("ascii")

    def descifrar(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError) as e:
            raise VaultCorrupto(
                "No se pudo descifrar el dato. ¿Fue editado a mano o pertenece "
                "a otra bóveda?"
            ) from e
