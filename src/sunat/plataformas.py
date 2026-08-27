"""Las plataformas de SUNAT a las que se puede entrar.

SUNAT no tiene un único portal: desde la misma clave SOL se entra a sitios
distintos según lo que vayas a hacer. Cada uno tiene su propia URL de
entrada y su propio `client_id` en el OAuth, aunque el formulario de login
sea el mismo.

Decisión de diseño: la plataforma es propiedad de la **sesión**, no de la
empresa. Las credenciales son idénticas —mismo RUC, usuario y clave—, así
que guardar una empresa por plataforma duplicaría la misma clave y obligaría
a cambiarla en dos sitios. Se elige el destino al momento de ingresar.

Verificado en vivo: ambas plataformas comparten la cabecera del menú
(`#aOpcionUsuario2`, `#btnSalir`), así que el marcador de "ya estoy dentro"
sirve para las dos y no hace falta parametrizarlo.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plataforma:
    id: str
    nombre: str
    url_entrada: str
    descripcion: str


TRAMITES = Plataforma(
    id="tramites",
    nombre="Mis Trámites y Consultas",
    url_entrada="https://e-menu.sunat.gob.pe/cl-ti-itmenucabina/MenuInternet.htm",
    descripcion="Buzón electrónico, RUC, deudas, expedientes.",
)

DECLARACIONES = Plataforma(
    id="declaraciones",
    nombre="Mis Declaraciones y Pagos",
    url_entrada="https://e-menu.sunat.gob.pe/cl-ti-itmenu2/MenuInternetPlataforma.htm",
    descripcion="Declarar y pagar, consultar declaraciones presentadas.",
)

# El orden importa: el primero es el destino por defecto.
TODAS: tuple[Plataforma, ...] = (TRAMITES, DECLARACIONES)

POR_DEFECTO = TRAMITES

_POR_ID = {p.id: p for p in TODAS}


def obtener(id_o_none: str | None) -> Plataforma:
    """Devuelve la plataforma pedida, o la de por defecto si no se indicó."""
    if not id_o_none:
        return POR_DEFECTO
    try:
        return _POR_ID[id_o_none]
    except KeyError:
        validas = ", ".join(_POR_ID)
        raise ValueError(
            f"Plataforma desconocida: {id_o_none!r}. Válidas: {validas}."
        ) from None


def ids() -> list[str]:
    return [p.id for p in TODAS]
