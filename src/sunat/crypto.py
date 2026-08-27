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
#
# 2**17 y no 2**15, que es lo que hubo hasta ahora. La diferencia importa
# porque el atacante realista no ataca esto en vivo: se lleva el token de
# dispositivo, pide al backend la cabecera de la bóveda y las claves
# cifradas, y prueba contraseñas sin conexión y sin límite de intentos.
#
# Medido en una máquina de escritorio corriente:
#
#     N=2^15    32 MB     77 ms
#     N=2^17   128 MB    267 ms   <- este
#     N=2^18   256 MB    576 ms
#
# 2^17 cuadruplica el costo del atacante y sigue siendo imperceptible al
# desbloquear, que ocurre una vez cada media hora. 2^18 sería mejor todavía,
# pero 256 MB en la laptop de 4 GB de un contador con Chrome abierto es pedir
# problemas, y una bóveda que a veces no abre es peor que una un poco menos
# dura.
#
# Los 128 MB no son un efecto secundario: son el punto. Una GPU tiene mucha
# memoria total pero muy poca por núcleo, así que el costo en memoria es lo
# que le impide probar miles de contraseñas en paralelo.
SCRYPT_N = 2**17  # ~128 MB de memoria
SCRYPT_R = 8
SCRYPT_P = 1
LONGITUD_LLAVE = 32
LONGITUD_SALT = 16

# Texto que se cifra al crear la bóveda; descifrarlo con éxito prueba que la
# contraseña maestra es correcta, sin tocar ninguna clave SOL.
TEXTO_VERIFICACION = b"sunat-launcher-vault-v1"

# Reglas al CREAR una bóveda. Ninguna se aplica al abrirla: una bóveda vieja
# puede tener cualquier contraseña, y exigirle la política nueva dejaría sus
# datos inaccesibles para siempre.
#
# Por qué hay política y no solo un mínimo de longitud: la contraseña maestra
# es el ÚNICO secreto que separa a un atacante con el token de dispositivo de
# todas las claves SOL, y las prueba sin conexión, sin límite de intentos y a
# la velocidad que le permita su hardware. Ahí un diccionario de las mil
# contraseñas más usadas se agota en minutos, por larga que sea cada una.
MINIMO_PASSWORD = 12

# A partir de esta longitud no se exige variedad de caracteres.
#
# "mi gato duerme sobre el teclado" tiene 31 caracteres y dos tipos, y es
# muchísimo más fuerte que "Sun@t24!". Obligar a meter símbolos en una frase
# larga solo consigue que la gente la acorte y la apunte en un papel.
LARGO_FRASE = 16

# Lo primero que prueba cualquier ataque por diccionario, más lo que la gente
# elige cuando el programa se llama "SUNAT Launcher". Se comparan sin tildes,
# en minúsculas y sin los dígitos del final: "Sunat2024" y "sunat" son la
# misma contraseña para quien ataca.
_COMUNES = frozenset(
    {
        "password", "contrasena", "contrasenia", "clave", "claveunica",
        "clavesol", "secreto", "admin", "administrador", "usuario",
        "qwerty", "qwertyui", "asdfgh", "asdfghjk", "zxcvbn", "123456",
        "1234567", "12345678", "123456789", "1234567890", "abcdef",
        "sunat", "sunatsol", "sol", "solsunat", "launcher", "sunatlauncher",
        "contador", "contabilidad", "estudio", "empresa", "facturacion",
        "peru", "lima", "arequipa", "cusco", "trujillo", "callao",
        "iloveyou", "teamo", "familia", "hola", "holamundo", "bienvenido",
    }
)

_SIMBOLOS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "


def _normalizar(password: str) -> str:
    """Minúsculas, sin tildes y sin los dígitos de los extremos.

    Es la forma en que un atacante ve la contraseña: su diccionario ya trae
    las variantes con acentos quitados y años pegados al final.
    """
    import unicodedata

    sin_tildes = "".join(
        c
        for c in unicodedata.normalize("NFD", password.lower())
        if unicodedata.category(c) != "Mn"
    )
    return sin_tildes.strip("0123456789 !@#$%.-_")


def _es_secuencia(password: str) -> bool:
    """Caracteres todos iguales, o corriendo hacia arriba o hacia abajo."""
    if len(set(password)) == 1:
        return True

    saltos = {ord(b) - ord(a) for a, b in zip(password, password[1:])}
    return saltos in ({1}, {-1})


def _tipos(password: str) -> int:
    return sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in _SIMBOLOS for c in password),
        )
    )


def validar_password_nueva(password: str) -> None:
    """Rechaza contraseñas que no aguantarían un ataque sin conexión.

    Lanza `PasswordDebil` con un motivo concreto: "no es válida" no le sirve
    a nadie que esté intentando elegir una.
    """
    if len(password) < MINIMO_PASSWORD:
        raise PasswordDebil(
            f"La contraseña maestra necesita al menos {MINIMO_PASSWORD} "
            f"caracteres; esta tiene {len(password)}. Una frase de varias "
            "palabras es más fácil de recordar y más difícil de adivinar que "
            "una palabra con símbolos."
        )

    if _es_secuencia(password):
        raise PasswordDebil(
            "Esa contraseña es una secuencia de teclas seguidas. Es de las "
            "primeras que se prueban."
        )

    if _normalizar(password) in _COMUNES:
        raise PasswordDebil(
            "Esa contraseña está en las listas que se prueban primero, aunque "
            "le cambies mayúsculas, tildes o le pegues un año al final. "
            "Elige algo que no se parezca a una palabra sola."
        )

    if len(password) < LARGO_FRASE and _tipos(password) < 3:
        raise PasswordDebil(
            "Con menos de "
            f"{LARGO_FRASE} caracteres hacen falta al menos tres de estos "
            "cuatro: minúsculas, mayúsculas, números y símbolos. La otra "
            "salida, y la mejor, es usar una frase larga: a partir de "
            f"{LARGO_FRASE} caracteres no se exige nada más."
        )


def parametros_debiles(params: "ParametrosKDF") -> bool:
    """Si esta bóveda se creó con un KDF más flojo que el de hoy.

    No se puede corregir sola: cambiar los parámetros obliga a volver a
    cifrar todas las claves con la llave nueva, y hacerlo a medias dejaría la
    bóveda ilegible. Sirve para avisar, que ya es mucho más que no saberlo.
    """
    return params.n < SCRYPT_N


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
