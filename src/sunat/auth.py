"""Autenticación contra SUNAT SOL.

Diseño en dos capas:

  - `iniciar_sesion` hace UN intento y clasifica el desenlace en un estado
    explícito, en vez de devolver un booleano ambiguo.
  - `iniciar_sesion_con_reintentos` decide qué estados vale la pena
    reintentar.

REGLA CRÍTICA: un rechazo de credenciales NUNCA se reintenta. SUNAT bloquea
el usuario SOL tras varios intentos fallidos consecutivos, así que un bucle
de reintentos "por si acaso" es la forma más rápida de dejar una empresa sin
acceso. Solo se reintentan fallas de red/timeout, que sí son transitorias.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, TimeoutError as PlaywrightTimeout

from . import plataformas
from . import selectors as sel
from .config import Config
from .log import obtener
from .plataformas import Plataforma
from .store import Empresa

_log = obtener("auth")


class EstadoLogin(str, Enum):
    OK = "ok"
    YA_AUTENTICADO = "ya_autenticado"
    CREDENCIALES_RECHAZADAS = "credenciales_rechazadas"
    REQUIERE_INTERVENCION = "requiere_intervencion"
    ERROR_TRANSITORIO = "error_transitorio"


@dataclass(frozen=True)
class ResultadoLogin:
    estado: EstadoLogin
    detalle: str = ""

    @property
    def exitoso(self) -> bool:
        return self.estado in (EstadoLogin.OK, EstadoLogin.YA_AUTENTICADO)

    @property
    def reintentable(self) -> bool:
        return self.estado is EstadoLogin.ERROR_TRANSITORIO


# --- helpers de detección ---------------------------------------------------


def _visible(page: Page, selector: str, *, limite: int = 5) -> bool:
    """¿Hay ALGÚN elemento visible que coincida?

    Mirar solo `.first` daba falsos negativos: con un selector combinado
    ("#a, #b") el primer match del DOM puede estar en un menú colapsado
    mientras el segundo sí se ve.
    """
    try:
        loc = page.locator(selector)
        for i in range(min(loc.count(), limite)):
            if loc.nth(i).is_visible():
                return True
        return False
    except PlaywrightError:
        return False


def _existe(page: Page, selector: str) -> bool:
    """Presencia en el DOM, sin exigir visibilidad."""
    try:
        return page.locator(selector).count() > 0
    except PlaywrightError:
        return False


def _esta_autenticado(page: Page, cfg: Config) -> bool:
    """¿Estamos dentro del Menú SOL?

    Solo es fiable DESPUÉS de enviar el formulario. Antes no lo es: la URL
    de entrada ya vive en e-menu.sunat.gob.pe y tarda ~0.5s en redirigir al
    formulario, así que en ese instante parece "menú sin login" sin serlo.
    Para el arranque usa `_esperar_pagina_inicial`.
    """
    url = page.url or ""
    if cfg.host_login in url or cfg.host_menu not in url:
        return False
    # Marcador POSITIVO ("Bienvenido, ..." / botón Salir). Deducirlo de la
    # ausencia del formulario daba falsos positivos mientras la página de
    # entrada todavía no había redirigido.
    #
    # Presencia, no visibilidad: la cabecera del menú tiene variantes
    # responsive ocultas según el ancho, y estos ids no existen fuera del
    # menú autenticado, así que estar en el DOM ya es señal suficiente.
    return _existe(page, sel.MARCADOR_MENU_AUTENTICADO)


def _esperar_pagina_inicial(page: Page, cfg: Config) -> str:
    """Espera a que la entrada se estabilice. Devuelve 'login'|'menu'|'?'.

    Medido en vivo: goto() retorna a los ~0.35s todavía en e-menu, y recién
    a los ~0.9s aparece el formulario en api-seguridad. Decidir antes de que
    eso ocurra daba un falso "ya había sesión activa".
    """
    limite = time.monotonic() + cfg.espera_formulario_ms / 1000
    while time.monotonic() < limite:
        if _visible(page, sel.RUC):
            return "login"
        if _esta_autenticado(page, cfg):
            return "menu"
        page.wait_for_timeout(250)
    return "?"


def _es_pagina_verificacion(page: Page) -> bool:
    """¿SUNAT está mostrando su página de verificación anti-bot?

    Es transitoria: significa "vas muy rápido", no "tus credenciales están
    mal". Distinguirla evita reportar un fallo que no lo es.
    """
    if _existe(page, sel.MARCADOR_VERIFICACION):
        return True
    try:
        return page.title().strip() == sel.TITULO_VERIFICACION
    except PlaywrightError:
        return False


def _texto_error(page: Page) -> str:
    try:
        return page.locator(sel.MENSAJE_ERROR).first.inner_text().strip()
    except PlaywrightError:
        return "(no se pudo leer el mensaje de error)"


def _aviso_sesion_activa(page: Page):
    """Devuelve el locator del aviso si está visible, o None."""
    try:
        loc = page.get_by_text(re.compile(sel.TEXTO_SESION_ACTIVA, re.IGNORECASE))
        if loc.count() > 0 and loc.first.is_visible():
            return loc.first
    except PlaywrightError:
        pass
    return None


def volcar_diagnostico(page: Page, cfg: Config, etiqueta: str) -> str | None:
    """Guarda HTML + captura para poder ajustar selectores después.

    Ojo: el volcado puede contener datos de la empresa en pantalla. Vive en
    la carpeta de datos local, nunca en el proyecto.
    """
    if not cfg.diagnostico:
        return None
    try:
        cfg.diagnostico_dir.mkdir(parents=True, exist_ok=True)
        marca = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = cfg.diagnostico_dir / f"{etiqueta}-{marca}"
        base.with_suffix(".html").write_text(page.content(), encoding="utf-8")
        page.screenshot(path=str(base.with_suffix(".png")), full_page=True)
        _log.info("Diagnóstico guardado en %s.(html|png)", base)
        return str(base)
    except Exception as e:  # el diagnóstico nunca debe romper el flujo
        _log.debug("No se pudo volcar diagnóstico: %s", e)
        return None


# --- un intento -------------------------------------------------------------


def _esperar_desenlace(page: Page, cfg: Config) -> ResultadoLogin:
    """Espera a que ocurra algo concluyente tras enviar el formulario.

    En vez de `wait_for_url` con un fallback, sondeamos las condiciones en
    paralelo: así un error del formulario se detecta al segundo, sin esperar
    el timeout completo.
    """
    limite = time.monotonic() + cfg.espera_login_ms / 1000
    sesion_ya_confirmada = False

    while time.monotonic() < limite:
        if _esta_autenticado(page, cfg):
            return ResultadoLogin(EstadoLogin.OK)

        if _visible(page, sel.MENSAJE_ERROR):
            return ResultadoLogin(EstadoLogin.CREDENCIALES_RECHAZADAS, _texto_error(page))

        if _visible(page, sel.INDICIOS_CAPTCHA):
            return ResultadoLogin(
                EstadoLogin.REQUIERE_INTERVENCION,
                "El formulario está pidiendo un captcha.",
            )

        if not sesion_ya_confirmada and _aviso_sesion_activa(page) is not None:
            _log.info("SUNAT avisa que ya había una sesión abierta; confirmando.")
            if _visible(page, sel.BOTON_CONTINUAR_SESION):
                try:
                    page.locator(sel.BOTON_CONTINUAR_SESION).first.click()
                    sesion_ya_confirmada = True  # no volver a intentarlo en bucle
                except PlaywrightError as e:
                    _log.debug("No se pudo pulsar el botón de continuar: %s", e)
            else:
                return ResultadoLogin(
                    EstadoLogin.REQUIERE_INTERVENCION,
                    "Aviso de sesión activa detectado, pero sin botón de "
                    "confirmación reconocible. Revisa selectors.py.",
                )

        page.wait_for_timeout(500)

    if _es_pagina_verificacion(page):
        return ResultadoLogin(
            EstadoLogin.ERROR_TRANSITORIO,
            "SUNAT está mostrando su página de verificación ('Bienvenidos a "
            "SUNAT'). Suele ser por varios ingresos seguidos desde la misma "
            "IP: espera unos minutos antes de reintentar.",
        )

    # Seguimos en el formulario, con los datos puestos y sin mensaje de error:
    # SUNAT recibió el envío y no hizo nada. Visto en la práctica cuando se
    # acumulan varios ingresos en poco rato desde la misma IP.
    if _visible(page, sel.RUC):
        return ResultadoLogin(
            EstadoLogin.ERROR_TRANSITORIO,
            "El formulario quedó lleno pero SUNAT no respondió al envío, y "
            "tampoco mostró un error. Suele pasar tras varios ingresos "
            "seguidos: espera unos minutos y vuelve a intentar. Si insiste, "
            "entra a SOL a mano una vez para descartar un aviso nuevo.",
        )

    return ResultadoLogin(
        EstadoLogin.REQUIERE_INTERVENCION,
        "El login no llegó al Menú SOL ni mostró un error reconocible.",
    )


def iniciar_sesion(
    page: Page,
    cfg: Config,
    empresa: Empresa,
    clave: str,
    plataforma: Plataforma | None = None,
) -> ResultadoLogin:
    """Un único intento de login. No reintenta nada.

    `plataforma` decide a qué portal de SUNAT se entra. El formulario y la
    cabecera del menú son los mismos en todas (verificado), así que lo único
    que cambia es la URL de entrada.
    """
    destino = plataforma or plataformas.POR_DEFECTO
    try:
        page.goto(destino.url_entrada)
    except (PlaywrightTimeout, PlaywrightError) as e:
        return ResultadoLogin(EstadoLogin.ERROR_TRANSITORIO, f"No cargó el portal: {e}")

    estado_inicial = _esperar_pagina_inicial(page, cfg)
    if estado_inicial == "menu":
        # El perfil persistente traía la sesión todavía viva.
        return ResultadoLogin(EstadoLogin.YA_AUTENTICADO)
    if estado_inicial == "?":
        return ResultadoLogin(
            EstadoLogin.ERROR_TRANSITORIO,
            "No apareció el formulario de login (portal lento o caído).",
        )

    try:
        page.fill(sel.RUC, empresa.ruc)
        # El campo usuario se pasa a mayúsculas por JS del propio formulario;
        # fill() dispara ese evento, así que no hace falta replicarlo.
        page.fill(sel.USUARIO, empresa.usuario)
        page.fill(sel.CLAVE, clave)
        page.click(sel.BOTON_INGRESAR)
    except (PlaywrightTimeout, PlaywrightError) as e:
        return ResultadoLogin(
            EstadoLogin.REQUIERE_INTERVENCION,
            f"El formulario no se comportó como se esperaba ({e}). "
            "Probablemente cambiaron los selectores.",
        )

    resultado = _esperar_desenlace(page, cfg)
    if resultado.estado is EstadoLogin.REQUIERE_INTERVENCION:
        volcar_diagnostico(page, cfg, f"login-{destino.id}-{empresa.ruc}")
    return resultado


# --- con reintentos ---------------------------------------------------------


def iniciar_sesion_con_reintentos(
    page: Page,
    cfg: Config,
    empresa: Empresa,
    clave: str,
    plataforma: Plataforma | None = None,
) -> ResultadoLogin:
    intentos = max(1, cfg.reintentos)
    resultado = ResultadoLogin(EstadoLogin.ERROR_TRANSITORIO, "sin intentos")

    for intento in range(1, intentos + 1):
        _log.debug("Intento de login %d/%d para %s", intento, intentos, empresa.ruc)
        resultado = iniciar_sesion(page, cfg, empresa, clave, plataforma)

        if resultado.exitoso or not resultado.reintentable:
            # Éxito, credenciales rechazadas o intervención: en los tres casos
            # insistir no ayuda (y en el segundo, hace daño).
            return resultado

        if intento < intentos:
            # Exponencial, no lineal: la causa transitoria más común es la
            # página de verificación por ir demasiado rápido, y ahí reintentar
            # enseguida solo empeora las cosas.
            espera = cfg.backoff_seg * (2 ** (intento - 1))
            _log.warning(
                "Intento %d falló (%s). Reintentando en %.0fs...",
                intento,
                resultado.detalle,
                espera,
            )
            time.sleep(espera)

    return resultado
