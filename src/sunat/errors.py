"""Excepciones propias del proyecto.

Todas heredan de SunatError para que la CLI pueda distinguir un error
esperado (que se muestra como mensaje limpio) de un bug real (que se
muestra con traceback).

Los desenlaces del login NO viven aquí: se modelan como estados en
`auth.EstadoLogin`, porque "credenciales rechazadas" no es una excepción
sino un resultado posible y esperado que hay que tratar distinto de un
timeout.
"""

from __future__ import annotations


class SunatError(Exception):
    """Error esperado y explicable al usuario."""


class VaultNoExiste(SunatError):
    pass


class VaultCorrupto(SunatError):
    pass


class ClaveMaestraInvalida(SunatError):
    pass


class PasswordDebil(SunatError):
    """La contraseña maestra propuesta es demasiado corta para una bóveda
    que no se puede recuperar."""


class EmpresaNoEncontrada(SunatError):
    pass

