"""Configuración centralizada.

Todo lo que alguna vez vas a querer ajustar sin tocar código vive aquí y
se puede sobrescribir por variable de entorno.

Decisión importante: los datos sensibles (vault, perfiles de Chrome con
cookies de sesión, logs) NO se guardan en la carpeta del proyecto, sino en
%LOCALAPPDATA%\\sunat-launcher\\. Así es imposible que terminen en un
repositorio por un .gitignore incompleto.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "sunat-launcher"

# Las URL de entrada viven en plataformas.py, una por portal de SUNAT.
#
# Ojo si alguna vez las tocas: www.sunat.gob.pe/sol.html NO sirve como
# entrada — es una página portal con enlaces y no redirige al formulario.

# Host del formulario de login (tras la redirección). Sirve para distinguir
# "estoy en el login" de "ya estoy dentro del menú".
HOST_LOGIN = "api-seguridad.sunat.gob.pe"

# Host del Menú SOL: estar aquí y no en el login significa sesión iniciada.
HOST_MENU = "e-menu.sunat.gob.pe"

# Orígenes del panel del SaaS que pueden hablarle al agente.
#
# El agente ya rechaza peticiones de cualquier otra página, pero antes el
# panel se servía desde el propio agente y la lista se deducía del puerto.
# Ahora el panel vive en la nube, así que sus orígenes son un dato del
# producto y tienen que estar aquí.
#
# El dominio de producción va HORNEADO aquí, no solo detrás de
# SUNAT_PANEL_ORIGENES: el .exe se distribuye a usuarios sin conocimientos
# técnicos, que no van a configurar una variable de entorno para que el
# panel les funcione. La variable queda disponible para dominios
# adicionales (un white-label, un ambiente de staging), no para este caso.
PANEL_ORIGENES = (
    "http://127.0.0.1:5173",
    "http://localhost:5173",
    "https://conta-beta-puce.vercel.app",
)

# A qué backends se deja vincular este agente.
#
# `validar_api_url` comprobaba solo el esquema, así que cualquier origen ya
# permitido —o un script inyectado en el panel— podía repuntar el agente a un
# servidor suyo con un único POST. Desde ahí le sirve al usuario una bóveda
# que no es la suya y recibe cada clave cifrada que guarde después.
#
# Horneado y no configurable por defecto, por lo mismo que PANEL_ORIGENES: el
# .exe lo instala gente que no va a poner una variable de entorno, y una
# lista blanca que el atacante puede ampliar desde la web no es una lista
# blanca.
BACKENDS_PERMITIDOS = ("https://conta-back-tq15.onrender.com",)

# El backend de desarrollo. Solo vale corriendo desde el código fuente: en el
# .exe empaquetado no se acepta, porque ahí no hay ningún motivo legítimo para
# vincular contra localhost y sí uno ilegítimo —un proceso local haciéndose
# pasar por el backend.
BACKENDS_LOCALES = (
    "http://127.0.0.1:4000",
    "http://localhost:4000",
)


def _empaquetado() -> bool:
    """Si estamos dentro del .exe de PyInstaller y no en el código fuente."""
    import sys

    return getattr(sys, "frozen", False)


# SUNAT corta la conexión (ERR_CONNECTION_RESET) con el user-agent que
# Chromium headless envía por defecto. Hay que mandar uno de navegador real.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def _raiz_proyecto() -> Path:
    # config.py está en src/sunat/, así que la raíz son dos niveles arriba.
    return Path(__file__).resolve().parents[2]


def cargar_dotenv() -> Path | None:
    """Lee un .env y lo vuelca al entorno, sin pisar lo que ya esté puesto.

    Existe para que no tengas que exportar variables a mano cada vez que
    abres una terminal. Las variables de entorno reales siguen ganando, que
    es lo que permite sobrescribir algo puntual para una sola ejecución.

    No usa python-dotenv a propósito: son veinte líneas y evita arrastrar
    una dependencia más al agente.
    """
    candidatos = [
        Path(os.environ.get("SUNAT_ENV_FILE", "")) if os.environ.get("SUNAT_ENV_FILE") else None,
        _raiz_proyecto() / ".env",
        _data_dir_por_defecto() / "config.env",
    ]

    for ruta in candidatos:
        if ruta is None or not ruta.is_file():
            continue
        try:
            contenido = ruta.read_text(encoding="utf-8")
        except OSError:
            continue

        for linea in contenido.splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            clave, _, valor = linea.partition("=")
            clave = clave.strip()
            valor = valor.strip().strip('"').strip("'")
            if clave and clave not in os.environ:
                os.environ[clave] = valor
        return ruta
    return None


def _env_str(nombre: str, default: str) -> str:
    valor = os.environ.get(nombre, "").strip()
    return valor or default


def _env_int(nombre: str, default: int) -> int:
    valor = os.environ.get(nombre, "").strip()
    if not valor:
        return default
    try:
        return int(valor)
    except ValueError:
        return default


def _env_bool(nombre: str, default: bool) -> bool:
    valor = os.environ.get(nombre, "").strip().lower()
    if not valor:
        return default
    return valor in {"1", "true", "yes", "si", "sí", "on"}


def _data_dir_por_defecto() -> Path:
    """Carpeta de datos del usuario, fuera del proyecto."""
    override = os.environ.get("SUNAT_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()

    # Windows
    local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
    if local_appdata:
        return Path(local_appdata) / APP_NAME

    # Linux / macOS, por si alguna vez se usa fuera de Windows
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg:
        return Path(xdg) / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


@dataclass(frozen=True)
class Config:
    data_dir: Path = field(default_factory=_data_dir_por_defecto)

    # Tiempos y reintentos (ver SUNAT_* en el README)
    timeout_ms: int = field(default_factory=lambda: _env_int("SUNAT_TIMEOUT_MS", 20_000))
    nav_timeout_ms: int = field(
        default_factory=lambda: _env_int("SUNAT_NAV_TIMEOUT_MS", 45_000)
    )
    espera_login_ms: int = field(
        default_factory=lambda: _env_int("SUNAT_ESPERA_LOGIN_MS", 30_000)
    )
    # Cuánto esperar a que la URL de entrada redirija al formulario. Medido:
    # ~0.9s en condiciones normales; el margen cubre un portal lento.
    espera_formulario_ms: int = field(
        default_factory=lambda: _env_int("SUNAT_ESPERA_FORMULARIO_MS", 15_000)
    )
    reintentos: int = field(default_factory=lambda: _env_int("SUNAT_REINTENTOS", 3))
    backoff_seg: float = field(
        default_factory=lambda: float(_env_int("SUNAT_BACKOFF_SEG", 3))
    )

    headless: bool = field(default_factory=lambda: _env_bool("SUNAT_HEADLESS", False))
    log_level: str = field(
        default_factory=lambda: _env_str("SUNAT_LOG_LEVEL", "INFO").upper()
    )
    # Guardar HTML + captura cuando el login termina en un estado desconocido.
    # Muy útil para diagnosticar cambios del portal; ver nota en el README.
    diagnostico: bool = field(
        default_factory=lambda: _env_bool("SUNAT_DIAGNOSTICO", True)
    )

    # Dónde se guardan las empresas. Si SUNAT_API_URL está definida se usa
    # el backend (MongoDB); si no, el archivo local de siempre. En ambos
    # casos la clave viaja YA cifrada: el cambio no afecta la seguridad.
    api_url: str = field(default_factory=lambda: _env_str("SUNAT_API_URL", ""))
    api_key: str = field(default_factory=lambda: _env_str("SUNAT_API_KEY", ""))

    # Orígenes del panel, además de los de PANEL_ORIGENES. Separados por coma.
    panel_origenes_extra: str = field(
        default_factory=lambda: _env_str("SUNAT_PANEL_ORIGENES", "")
    )

    # Backends adicionales a los que se puede vincular, separados por coma.
    #
    # Una variable de entorno y no un dato que llegue por HTTP: quien puede
    # ponerla ya ejecuta código en esta máquina, así que no le da nada nuevo;
    # una página, en cambio, no puede tocarla. Esa es toda la diferencia entre
    # esto y el agujero que cierra la lista blanca.
    backends_extra: str = field(default_factory=lambda: _env_str("SUNAT_BACKENDS", ""))

    # A dónde abre "Abrir panel" en el ícono de la bandeja. El agente ya no
    # sirve el panel él mismo —vive en un repo aparte, en la nube o en
    # :5173 en desarrollo— así que tiene que saber la URL por fuera.
    panel_url: str = field(
        default_factory=lambda: _env_str("SUNAT_PANEL_URL", "http://127.0.0.1:5173")
    )

    host_login: str = HOST_LOGIN
    host_menu: str = HOST_MENU
    user_agent: str = field(
        default_factory=lambda: _env_str("SUNAT_USER_AGENT", USER_AGENT)
    )

    # A dónde van los archivos que se descargan dentro de SUNAT (buzón,
    # constancias, etc.). La carpeta de Descargas de siempre, no la del
    # proyecto: es el lugar donde el usuario ya sabe buscar.
    descargas_dir: Path = field(
        default_factory=lambda: Path(
            _env_str("SUNAT_DESCARGAS_DIR", str(Path.home() / "Downloads"))
        )
    )

    @property
    def vault_file(self) -> Path:
        return self.data_dir / "vault.json"

    @property
    def profiles_dir(self) -> Path:
        return self.data_dir / "profiles"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def diagnostico_dir(self) -> Path:
        return self.logs_dir / "diagnostico"

    def perfil_de(self, ruc: str, plataforma: str = "tramites") -> Path:
        """Un perfil de Chrome por RUC y plataforma.

        Separarlos evita que dos sesiones del mismo RUC compartan cookies y
        se pisen entre sí.

        El orden es <plataforma>/<RUC> y no <RUC>/<plataforma> a propósito:
        con el segundo, quien ya tenía un perfil del esquema anterior en
        `profiles/<RUC>/` acababa con un perfil de Chrome DENTRO de otro
        perfil de Chrome. Poniendo la plataforma primero, el nivel de arriba
        es siempre una carpeta contenedora y nunca un perfil.
        """
        return self.profiles_dir / plataforma / ruc

    def perfiles_del_esquema_viejo(self) -> list[Path]:
        """Restos de esquemas anteriores en el primer nivel de `profiles/`.

        Hoy ese nivel contiene solo ids de plataforma, así que cualquier
        carpeta cuyo nombre sea un RUC viene de antes: del esquema original
        (`profiles/<RUC>/`) o del intermedio (`profiles/<RUC>/<plataforma>/`).

        Se pueden borrar sin perder nada: solo guardaban cookies, y SUNAT no
        reutiliza la sesión entre ejecuciones.
        """
        if not self.profiles_dir.is_dir():
            return []
        return [
            d for d in self.profiles_dir.iterdir() if d.is_dir() and d.name.isdigit()
        ]

    def origenes_del_panel(self) -> list[str]:
        """Todos los orígenes del panel: los del producto más los extra."""
        extra = [
            o.strip().rstrip("/")
            for o in self.panel_origenes_extra.split(",")
            if o.strip()
        ]
        # dict.fromkeys y no set: el orden importa para los mensajes de error.
        return list(dict.fromkeys([*PANEL_ORIGENES, *extra]))

    def backends_permitidos(self) -> list[str]:
        """A qué backends se deja vincular esta instalación.

        Los locales entran solo corriendo desde el código fuente. En el .exe
        que usa el contador, vincular contra localhost no resuelve ningún caso
        real y sí abre uno malo, así que ahí no está.
        """
        extra = [
            b.strip().rstrip("/") for b in self.backends_extra.split(",") if b.strip()
        ]
        locales = [] if _empaquetado() else list(BACKENDS_LOCALES)
        return list(dict.fromkeys([*BACKENDS_PERMITIDOS, *locales, *extra]))

    def asegurar_directorios(self) -> None:
        for carpeta in (self.data_dir, self.profiles_dir, self.logs_dir):
            carpeta.mkdir(parents=True, exist_ok=True)


def cargar_config() -> Config:
    # El .env se lee ANTES de construir Config: sus campos leen el entorno
    # en el momento de la construcción.
    cargar_dotenv()
    cfg = Config()
    cfg.asegurar_directorios()
    return cfg


def limpiar_perfiles_viejos(cfg: Config) -> list[str]:
    """Borra los perfiles sueltos que dejó el esquema anterior.

    Antes el perfil era `profiles/<RUC>/`; ahora es
    `profiles/<plataforma>/<RUC>/`. Sin esta limpieza quedaba un perfil de
    Chrome conteniendo otro perfil de Chrome, que es una situación que nadie
    diseñó y que no conviene dejar por ahí.

    Se pueden borrar sin perder nada: solo guardaban cookies, y SUNAT no
    reutiliza la sesión entre ejecuciones.
    """
    import shutil

    borrados = []
    for ruta in cfg.perfiles_del_esquema_viejo():
        shutil.rmtree(ruta, ignore_errors=True)
        # ignore_errors deja pasar un perfil en uso; se reintenta al
        # siguiente arranque y mientras tanto no estorba.
        if not ruta.exists():
            borrados.append(ruta.name)
    return borrados


def crear_repositorio(cfg: Config):
    """El repositorio que toca según la configuración.

    El orden no es arbitrario. La vinculación gana sobre las variables de
    entorno porque es lo que el usuario eligió desde el panel, con un token
    propio y revocable; `SUNAT_API_URL` es el modo anterior, de una sola
    llave compartida, y se conserva solo para no romper instalaciones que
    ya lo usaban.
    """
    from .repositorios import RepositorioApi, RepositorioArchivo
    from .vinculacion import leer as leer_vinculacion

    vinculo = leer_vinculacion(cfg)
    if vinculo:
        return RepositorioApi(vinculo.api_url, vinculo.token)

    if cfg.api_url:
        return RepositorioApi(cfg.api_url, cfg.api_key)

    return RepositorioArchivo(cfg.vault_file)
