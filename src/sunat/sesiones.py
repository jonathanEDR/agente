"""Navegadores abiertos, cada uno en su propio hilo.

Por qué hilos: la API síncrona de Playwright bloquea, y `esperar_cierre_manual`
se queda esperando a que cierres Chrome. Si eso corriera en el hilo de
Tkinter, la ventana se congelaría.

Regla de Playwright que condiciona el diseño: un objeto de Playwright solo
se puede usar en el hilo que lo creó. Por eso cada hilo abre su propio
`sync_playwright()` (dentro de `sesion_navegador`) y nunca comparte el
navegador con la ventana. La comunicación va en un solo sentido y por cola.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, replace

from . import plataformas
from .auth import EstadoLogin, ResultadoLogin, iniciar_sesion_con_reintentos
from playwright.sync_api import Error as PlaywrightError

from .browser import esperar_cierre_manual, sesion_navegador
from .config import Config
from .log import obtener
from .plataformas import Plataforma
from .store import Empresa

_log = obtener("gui.sesiones")


@dataclass(frozen=True)
class Evento:
    """Novedad de una sesión, para que la ventana se actualice."""

    ruc: str
    tipo: str  # "abriendo" | "listo" | "fallo" | "cerrado"
    mensaje: str = ""
    estado: EstadoLogin | None = None
    plataforma: str = plataformas.POR_DEFECTO.id


class GestorSesiones:
    def __init__(self, cfg: Config) -> None:
        # La GUI siempre abre navegador visible: el sentido de esta pantalla
        # es que después navegues tú.
        self.cfg = replace(cfg, headless=False)
        self.eventos: queue.Queue[Evento] = queue.Queue()
        self._hilos: dict[tuple[str, str], threading.Thread] = {}
        self._lock = threading.Lock()

    # --- consulta -----------------------------------------------------------

    def abierta(self, ruc: str, plataforma: str | None = None) -> bool:
        """¿Hay un navegador vivo para este RUC en esta plataforma?

        Con dos plataformas, la misma empresa puede estar abierta en una y
        cerrada en la otra: la clave del registro es el par, no el RUC solo.
        """
        clave = (ruc, plataforma or plataformas.POR_DEFECTO.id)
        with self._lock:
            hilo = self._hilos.get(clave)
            return hilo is not None and hilo.is_alive()

    def abiertas(self) -> list[tuple[str, str]]:
        """Pares (ruc, plataforma) con navegador vivo."""
        with self._lock:
            return [c for c, h in self._hilos.items() if h.is_alive()]

    def rucs_abiertos(self) -> list[str]:
        """RUC con al menos una plataforma abierta."""
        return sorted({ruc for ruc, _ in self.abiertas()})

    # --- apertura -----------------------------------------------------------

    def abrir(
        self, empresa: Empresa, clave: str, plataforma: Plataforma | None = None
    ) -> bool:
        """Lanza el login en segundo plano. False si ya estaba abierta."""
        destino = plataforma or plataformas.POR_DEFECTO
        if self.abierta(empresa.ruc, destino.id):
            return False

        hilo = threading.Thread(
            target=self._trabajar,
            args=(empresa, clave, destino),
            name=f"sesion-{empresa.ruc}-{destino.id}",
            daemon=True,
        )
        with self._lock:
            self._hilos[(empresa.ruc, destino.id)] = hilo
        hilo.start()
        return True

    def _trabajar(self, empresa: Empresa, clave: str, destino: Plataforma) -> None:
        ruc = empresa.ruc
        self.eventos.put(
            Evento(ruc, "abriendo", f"Abriendo {destino.nombre}...", plataforma=destino.id)
        )
        try:
            with sesion_navegador(self.cfg, ruc, plataforma=destino.id) as (context, page):
                resultado = iniciar_sesion_con_reintentos(
                    page, self.cfg, empresa, clave, destino
                )
                del clave  # ya no hace falta en memoria

                self.eventos.put(self._evento_de(ruc, resultado, destino.id))

                if resultado.exitoso or resultado.estado is EstadoLogin.REQUIERE_INTERVENCION:
                    # En ambos casos la ventana sigue siendo útil: o para
                    # navegar, o para que el usuario resuelva a mano.
                    motivo = esperar_cierre_manual(context)
                    if motivo != "cerrado":
                        self.eventos.put(
                            Evento(
                                ruc,
                                "fallo",
                                f"La ventana dejó de responder: {motivo}",
                                plataforma=destino.id,
                            )
                        )
        except PlaywrightError as e:
            # Lo más común: el navegador se cerró mientras aún se estaba
            # autenticando. Como mensaje suelto no dice nada, así que se
            # explica en términos de lo que la persona vio.
            primera = str(e).splitlines()[0]
            if "closed" in primera.lower():
                texto = (
                    f"El navegador de {destino.nombre} se cerró antes de "
                    "terminar de entrar. Si no lo cerraste tú, vuelve a "
                    "intentarlo; el detalle está en el log."
                )
            else:
                texto = f"Falló el navegador: {primera}"
            _log.warning("Sesión de %s en %s: %s", ruc, destino.id, primera)
            self.eventos.put(Evento(ruc, "fallo", texto, plataforma=destino.id))
        except Exception as e:  # noqa: BLE001 - la GUI debe sobrevivir a todo
            _log.exception("Fallo en la sesión de %s", ruc)
            self.eventos.put(
                Evento(ruc, "fallo", f"Error inesperado: {e}", plataforma=destino.id)
            )
        finally:
            self.eventos.put(
                Evento(ruc, "cerrado", "Navegador cerrado.", plataforma=destino.id)
            )

    @staticmethod
    def _evento_de(ruc: str, r: ResultadoLogin, plataforma: str) -> Evento:
        if r.estado is EstadoLogin.OK:
            return Evento(ruc, "listo", "Sesión iniciada.", r.estado, plataforma)
        if r.estado is EstadoLogin.YA_AUTENTICADO:
            return Evento(ruc, "listo", "Ya había sesión activa.", r.estado, plataforma)
        if r.estado is EstadoLogin.CREDENCIALES_RECHAZADAS:
            return Evento(
                ruc,
                "fallo",
                f"SUNAT rechazó el acceso: {r.detalle} "
                "(no se reintenta: bloquearía el usuario SOL)",
                r.estado,
                plataforma,
            )
        if r.estado is EstadoLogin.REQUIERE_INTERVENCION:
            return Evento(
                ruc, "fallo", f"Necesita tu intervención: {r.detalle}", r.estado, plataforma
            )
        return Evento(
            ruc, "fallo", r.detalle or "No se pudo iniciar sesión.", r.estado, plataforma
        )
