"""Agente local: la API que usa el panel web.

Escucha solo en 127.0.0.1 y hace tres cosas que el navegador no puede:
guardar la contraseña maestra en memoria, cifrar y descifrar las claves
SOL, y abrir Chrome en tu pantalla.

Por qué el cifrado vive aquí y no en el panel: si el React hablara directo
con MongoDB tendría que reimplementar scrypt y Fernet en JavaScript, y dos
implementaciones que difieran en un detalle producen claves que después no
se pueden descifrar. Con el agente en medio hay una sola implementación, la
que ya está probada.

Seguridad, en tres capas:

  1. Escucha en 127.0.0.1, nunca en la red.
  2. Comprueba `Origin` y `Host`: una página cualquiera que visites puede
     intentar peticiones contra tu localhost, y sin esto tendría éxito.
  3. Exige un token que se genera al arrancar. El panel lo recibe inyectado
     en su HTML, así que nunca hay que copiarlo a mano.
"""

from __future__ import annotations

import asyncio
import json
import queue
import secrets
import time
from dataclasses import replace
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import plataformas, vinculacion
from . import __version__
from .config import Config, cargar_config, crear_repositorio, limpiar_perfiles_viejos
from .errors import SunatError
from .log import configurar, obtener
from .repositorios import RepositorioApi, TokenRechazado
from .sesiones import Evento, GestorSesiones
from .store import Vault

_log = obtener("agente")

PUERTO_POR_DEFECTO = 17817
HOST = "127.0.0.1"

# Tras este rato sin actividad, la bóveda se vuelve a bloquear y hay que
# escribir la contraseña maestra otra vez.
MINUTOS_INACTIVIDAD = 30

# Cuánto se recuerda lo que dijo el backend antes de volver a preguntarle.
#
# El panel consulta /api/estado cada 5 segundos y cada consulta hacía un viaje
# de ida y vuelta a Render: 12 peticiones por minuto para responder algo que
# casi nunca cambia.
#
# Con el token revocado eso además eran 12 RECHAZOS por minuto, suficiente
# para que el limitador del backend empiece a responder 429 — y entonces el
# agente ya no puede distinguir "me revocaron" de "el backend está saturado",
# que es justo la diferencia que el usuario necesita ver.
SEGUNDOS_SONDEO = 20

# Un token revocado no se arregla solo: lo único que lo cambia es volver a
# vincular, y eso invalida este recuerdo explícitamente. No tiene sentido
# seguir preguntando cada veinte segundos.
SEGUNDOS_SONDEO_RECHAZADO = 120


class Backend:
    """Lo último que se supo del backend."""

    def __init__(self, existe: bool, ok: bool, revocado: bool, detalle: str) -> None:
        self.existe = existe
        self.ok = ok
        self.revocado = revocado
        self.detalle = detalle


class Estado:
    """Lo que el proceso recuerda mientras vive.

    La contraseña maestra nunca se guarda: lo que queda en memoria es el
    `Vault` ya abierto, y solo hasta que se bloquea o se cierra el agente.
    """

    def __init__(self, cfg: Config, token: str) -> None:
        self.cfg = cfg
        self.token = token
        self.vault: Vault | None = None
        self.gestor = GestorSesiones(cfg)
        self.ultimo_uso = time.monotonic()
        # Cada cliente SSE recibe su propia copia de los eventos.
        self._suscriptores: list[queue.Queue[Evento]] = []
        # (cuándo caduca, qué se supo). Ver SEGUNDOS_SONDEO.
        self._sondeo: tuple[float, Backend] | None = None

    # --- backend ------------------------------------------------------------

    def sondear_backend(self, repo) -> Backend:
        """Si el backend responde y si la bóveda existe, con memoria corta."""
        ahora = time.monotonic()
        if self._sondeo is not None and ahora < self._sondeo[0]:
            return self._sondeo[1]

        try:
            info = Backend(existe=repo.existe(), ok=True, revocado=False, detalle="")
            ttl = SEGUNDOS_SONDEO
        except TokenRechazado as e:
            info = Backend(existe=False, ok=False, revocado=True, detalle=str(e))
            ttl = SEGUNDOS_SONDEO_RECHAZADO
        except SunatError as e:
            info = Backend(existe=False, ok=False, revocado=False, detalle=str(e))
            ttl = SEGUNDOS_SONDEO

        self._sondeo = (ahora + ttl, info)
        return info

    def olvidar_sondeo(self) -> None:
        """Tras vincular, desvincular o crear la bóveda, lo recordado ya no vale."""
        self._sondeo = None

    # --- bóveda -------------------------------------------------------------

    @property
    def bloqueada(self) -> bool:
        self._caducar_si_toca()
        return self.vault is None

    def tocar(self) -> None:
        self.ultimo_uso = time.monotonic()

    def _caducar_si_toca(self) -> None:
        if self.vault is None:
            return
        if time.monotonic() - self.ultimo_uso > MINUTOS_INACTIVIDAD * 60:
            _log.info("Bóveda bloqueada por inactividad.")
            self.vault = None

    def exigir_vault(self) -> Vault:
        if self.bloqueada:
            raise _Bloqueada()
        self.tocar()
        assert self.vault is not None
        return self.vault

    # --- eventos ------------------------------------------------------------

    def suscribir(self) -> queue.Queue[Evento]:
        cola: queue.Queue[Evento] = queue.Queue()
        self._suscriptores.append(cola)
        return cola

    def desuscribir(self, cola: queue.Queue[Evento]) -> None:
        if cola in self._suscriptores:
            self._suscriptores.remove(cola)

    def repartir_eventos(self) -> None:
        """Pasa lo que produjeron los hilos a cada cliente conectado."""
        while True:
            try:
                evento = self.gestor.eventos.get_nowait()
            except queue.Empty:
                return
            for cola in list(self._suscriptores):
                cola.put(evento)


class _Bloqueada(SunatError):
    def __init__(self) -> None:
        super().__init__("La bóveda está bloqueada. Escribe tu contraseña maestra.")


# --- cuerpos de las peticiones ----------------------------------------------
#
# A nivel de módulo, no dentro de crear_app(): con `from __future__ import
# annotations` las anotaciones son cadenas, y FastAPI no puede resolver el
# nombre de una clase que solo existe dentro de una función. El síntoma es
# un 422 en todas las rutas con cuerpo, sin explicación aparente.


class Desbloqueo(BaseModel):
    password: str = Field(min_length=1)


class EmpresaEntrada(BaseModel):
    nombre: str = Field(min_length=1)
    ruc: str = Field(pattern=r"^\d{11}$")
    usuario: str = Field(min_length=1)
    # Vacía al editar = conservar la que ya estaba.
    clave: str = ""


class Ingreso(BaseModel):
    ruc: str = Field(pattern=r"^\d{11}$")
    # Vacía = la plataforma por defecto, para que un cliente viejo siga
    # funcionando sin cambios.
    plataforma: str = ""


class Vinculo(BaseModel):
    """Lo que el panel entrega para vincular esta computadora."""

    token: str = Field(min_length=1)
    api_url: str = Field(min_length=1)


# --- construcción de la app -------------------------------------------------


def crear_app(cfg: Config, token: str, puerto: int) -> FastAPI:
    estado = Estado(cfg, token)
    app = FastAPI(title="SUNAT SOL — agente local", docs_url=None, redoc_url=None)
    app.state.estado = estado

    # El panel servido por el propio agente, más el del SaaS.
    #
    # Los dos siguen valiendo a propósito: la ventana de escritorio y
    # `sunat agente` sin nube tienen que seguir funcionando igual que antes.
    origenes_ok = {
        f"http://{HOST}:{puerto}",
        f"http://localhost:{puerto}",
        *cfg.origenes_del_panel(),
    }
    hosts_ok = {f"{HOST}:{puerto}", f"localhost:{puerto}"}

    # --- guardas ------------------------------------------------------------

    @app.middleware("http")
    async def comprobar_procedencia(request: Request, call_next):
        """Rechaza peticiones que vengan de otra página.

        Sin esto, cualquier sitio que visites podría pedirle al agente que
        abra sesiones: el navegador enviaría la petición con gusto porque
        127.0.0.1 es alcanzable desde cualquier origen.
        """
        origen = request.headers.get("origin")
        if origen and origen not in origenes_ok:
            return _json_error(403, f"Origen no permitido: {origen}")

        # Defensa contra DNS rebinding: un dominio que resuelva a 127.0.0.1
        # llegaría aquí con su propio Host.
        host = (request.headers.get("host") or "").lower()
        if host and host not in hosts_ok:
            return _json_error(403, f"Host no permitido: {host}")

        return await call_next(request)

    # CORS va DESPUÉS de registrar la guarda de arriba, y no antes.
    #
    # Starlette aplica los middlewares en orden inverso al de registro, así
    # que este queda por fuera y es quien responde el preflight `OPTIONS`.
    # Al revés, la guarda de procedencia contestaría 403 al preflight —que
    # el navegador manda sin credenciales— y ninguna llamada del panel
    # llegaría nunca al agente.
    #
    # Antes no hacía falta CORS en absoluto: el panel lo servía el propio
    # agente, así que todo era del mismo origen. Ahora el panel viene de la
    # nube y sin esto el navegador corta cada petición.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=sorted(origenes_ok),
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Agent-Token"],
    )

    def exigir_token(x_agent_token: str = Header(default="")) -> None:
        if not secrets.compare_digest(x_agent_token, token):
            raise HTTPException(401, "Token del agente inválido.")

    protegido = [Depends(exigir_token)]

    # --- errores ------------------------------------------------------------

    @app.exception_handler(SunatError)
    async def _sunat_error(_request, exc: SunatError):
        codigo = 423 if isinstance(exc, _Bloqueada) else 400
        return _json_error(codigo, str(exc))

    # --- vinculación --------------------------------------------------------

    @app.get("/api/handshake")
    def handshake() -> dict[str, Any]:
        """Entrega el token del agente al panel. La única ruta sin token.

        Cuando el panel lo servía el propio agente, el token venía inyectado
        en el HTML. El panel ahora se sirve desde la nube y esa vía ya no
        existe, así que hay que entregarlo por aquí.

        Lo que la protege es la guarda de procedencia: solo responde a los
        orígenes que el agente reconoce, y `Access-Control-Allow-Origin` hace
        que ningún otro pueda leer la respuesta. Es la misma frontera que
        tenía la inyección en el HTML, no una más débil.

        Un proceso local sí puede pedirlo sin `Origin` — pero ese proceso ya
        podría leer `agente.token` del disco, así que no gana nada nuevo.
        """
        vinculo = vinculacion.leer(cfg)
        return {
            "agente": "sunat-launcher",
            # Que version corre. Sin esto no hay forma de saber, desde el
            # panel, si el .exe en uso trae un arreglo o es de antes.
            "version": __version__,
            "token": token,
            "vinculado": vinculo is not None,
            "api_url": vinculo.api_url if vinculo else "",
        }

    @app.post("/api/vincular", dependencies=protegido)
    def vincular(cuerpo: Vinculo) -> dict[str, Any]:
        """Guarda el token de dispositivo que el panel pidió al backend.

        El orden es: validar, PROBAR, y solo entonces escribir.

        Antes se guardaba primero y se probaba después, deshaciendo con
        `olvidar()` si el backend rechazaba el token. El problema es que
        `olvidar()` borra el archivo entero, no restaura lo que había: un
        intento fallido de vincular dejaba sin vinculación a una computadora
        que sí la tenía, y el token anterior no se puede recuperar porque el
        backend solo lo muestra una vez.

        Probando antes de escribir, un intento fallido no toca nada.
        """
        url = vinculacion.validar_api_url(cuerpo.api_url, cfg.backends_permitidos())

        # Se comprueba en el acto. Vincular contra un backend que no responde
        # deja al usuario con un "vinculado" que falla recién en la primera
        # acción real, y ahí ya no es evidente que la causa fue esto.
        try:
            RepositorioApi(url, cuerpo.token).existe()
        except SunatError as e:
            raise HTTPException(400, f"No se pudo hablar con el backend: {e}") from e

        vinculacion.guardar(cfg, cuerpo.token, url)
        repo = crear_repositorio(cfg)

        # La bóveda abierta se derivó del salt del almacenamiento anterior;
        # contra el nuevo no descifra nada. Bloquear obliga a escribir la
        # contraseña maestra otra vez, que es lo correcto.
        estado.vault = None
        estado.olvidar_sondeo()

        _log.info("Agente vinculado a %s", repo.describir())
        return {"ok": True, "origen": repo.describir()}

    @app.post("/api/desvincular", dependencies=protegido)
    def desvincular() -> dict[str, Any]:
        """Olvida la vinculación local y vuelve al archivo de siempre.

        No revoca nada en el backend: para eso está el panel, que puede
        hacerlo sin tener esta computadora delante — que es justo el caso
        de una máquina perdida.
        """
        habia = vinculacion.olvidar(cfg)
        estado.vault = None
        estado.olvidar_sondeo()
        return {"ok": True, "habia_vinculacion": habia}

    # --- estado -------------------------------------------------------------

    @app.get("/api/estado", dependencies=protegido)
    def estado_actual() -> dict[str, Any]:
        repo = crear_repositorio(cfg)
        backend = estado.sondear_backend(repo)

        return {
            "bloqueada": estado.bloqueada,
            "boveda_creada": backend.existe,
            # "El backend me rechazó" no es lo mismo que "el backend no
            # responde": el primero se arregla volviendo a vincular y el
            # segundo esperando. Sin separarlos, el panel mandaba a esperar a
            # quien tenía que volver a vincular, y encima no le ofrecía dónde.
            "token_revocado": backend.revocado,
            # Solo se sabe con la bóveda abierta: los parámetros viajan en su
            # cabecera y leerla exige haber desbloqueado.
            "kdf_debil": estado.vault.kdf_debil if estado.vault else False,
            "origen": repo.describir(),
            "vinculado": vinculacion.leer(cfg) is not None,
            "backend_ok": backend.ok,
            "detalle": backend.detalle,
            # Pares (ruc, plataforma): la misma empresa puede estar abierta
            # en una plataforma y cerrada en la otra.
            "abiertas": [
                {"ruc": r, "plataforma": pf} for r, pf in estado.gestor.abiertas()
            ],
            # El panel dibuja el menú de destinos con esto, así que agregar
            # una plataforma nueva no obliga a tocar el frontend.
            "plataformas": [
                {"id": pf.id, "nombre": pf.nombre, "descripcion": pf.descripcion}
                for pf in plataformas.TODAS
            ],
            "plataforma_por_defecto": plataformas.POR_DEFECTO.id,
        }

    @app.post("/api/desbloquear", dependencies=protegido)
    def desbloquear(cuerpo: Desbloqueo) -> dict[str, Any]:
        repo = crear_repositorio(cfg)
        if repo.existe():
            estado.vault = Vault.abrir(repo, cuerpo.password)
            creada = False
        else:
            estado.vault = Vault.crear(repo, cuerpo.password)
            creada = True
            _log.info("Bóveda creada en %s", repo.describir())

        # La bóveda pasó a existir, o se confirmó que ya estaba: lo que se
        # recordara de antes queda viejo.
        estado.olvidar_sondeo()
        estado.tocar()

        if estado.vault.kdf_debil:
            _log.warning(
                "Esta bóveda se creó con parámetros de cifrado anteriores y "
                "resiste bastante menos ante un ataque sin conexión. Para "
                "subirlos hay que crear una bóveda nueva y volver a registrar "
                "las empresas."
            )

        return {
            "ok": True,
            "boveda_creada_ahora": creada,
            "kdf_debil": estado.vault.kdf_debil,
        }

    @app.post("/api/bloquear", dependencies=protegido)
    def bloquear() -> dict[str, bool]:
        estado.vault = None
        return {"ok": True}

    # --- empresas -----------------------------------------------------------

    @app.get("/api/empresas", dependencies=protegido)
    def listar_empresas() -> list[dict[str, Any]]:
        vault = estado.exigir_vault()
        abiertas: dict[str, list[str]] = {}
        for ruc, pf in estado.gestor.abiertas():
            abiertas.setdefault(ruc, []).append(pf)

        return [
            {
                "ruc": e.ruc,
                "nombre": e.nombre,
                "usuario": e.usuario,
                "abiertas": abiertas.get(e.ruc, []),
            }
            for e in vault.listar()
        ]

    @app.put("/api/empresas/{ruc}", dependencies=protegido)
    def guardar_empresa(ruc: str, cuerpo: EmpresaEntrada) -> dict[str, Any]:
        vault = estado.exigir_vault()
        if cuerpo.ruc != ruc:
            raise HTTPException(400, "El RUC de la ruta y el del cuerpo no coinciden.")

        clave = cuerpo.clave
        if not clave:
            # Editar sin escribir clave conserva la actual; si la empresa es
            # nueva, no hay nada que conservar.
            try:
                clave = vault.clave_de(vault.obtener(ruc))
            except SunatError as e:
                raise HTTPException(400, f"La clave SOL es obligatoria. {e}") from e

        vault.upsert(cuerpo.nombre, ruc, cuerpo.usuario, clave)
        return {"ok": True}

    @app.delete("/api/empresas/{ruc}", dependencies=protegido)
    def eliminar_empresa(ruc: str) -> dict[str, bool]:
        estado.exigir_vault().eliminar(ruc)
        return {"ok": True}

    # --- sesiones -----------------------------------------------------------

    @app.post("/api/sesiones", dependencies=protegido)
    def abrir_sesion(cuerpo: Ingreso) -> dict[str, Any]:
        vault = estado.exigir_vault()
        empresa = vault.obtener(cuerpo.ruc)
        try:
            destino = plataformas.obtener(cuerpo.plataforma)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

        if estado.gestor.abierta(empresa.ruc, destino.id):
            return {
                "ok": False,
                "motivo": f"{empresa.nombre} ya está abierta en {destino.nombre}.",
            }

        estado.gestor.abrir(empresa, vault.clave_de(empresa), destino)
        return {"ok": True, "plataforma": destino.id}

    @app.get("/api/eventos")
    async def eventos(request: Request, token_query: str = Query("", alias="token")):
        """Estado de las sesiones en vivo, por Server-Sent Events.

        El flujo es de un solo sentido —el agente informa, el panel escucha—
        así que SSE basta y evita el handshake de WebSockets.

        Esta ruta acepta el token por query además de por cabecera, porque
        `EventSource` no permite enviar cabeceras propias. Es admisible
        aquí: la conexión no sale de 127.0.0.1, y las guardas de Origin y
        Host siguen aplicando. Solo para esta ruta, que no muta nada.
        """
        recibido = request.headers.get("x-agent-token", "") or token_query
        if not secrets.compare_digest(recibido, token):
            raise HTTPException(401, "Token del agente inválido.")

        cola = estado.suscribir()

        async def emitir():
            try:
                yield ": conectado\n\n"
                while True:
                    if await request.is_disconnected():
                        return
                    estado.repartir_eventos()
                    try:
                        while True:
                            ev = cola.get_nowait()
                            datos = {
                                "ruc": ev.ruc,
                                "tipo": ev.tipo,
                                "mensaje": ev.mensaje,
                                "plataforma": ev.plataforma,
                            }
                            yield f"data: {json.dumps(datos, ensure_ascii=False)}\n\n"
                    except queue.Empty:
                        pass
                    # Comentario periódico: mantiene viva la conexión y
                    # permite notar el corte si el panel se cierra.
                    yield ": ping\n\n"
                    await asyncio.sleep(0.4)
            finally:
                estado.desuscribir(cola)

        return StreamingResponse(
            emitir(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # --- pagina informativa ---------------------------------------------------
    #
    # El agente ya no sirve el panel: eso vive en un repo aparte (React,
    # desplegado en Vercel o corriendo en :5173 en desarrollo). Esta ruta
    # es solo para quien llegue a http://127.0.0.1:<puerto> a mano —el
    # ícono de bandeja no la usa, abre directo la URL del panel real.

    @app.get("/")
    def raiz():
        return HTMLResponse(_pagina_agente_corriendo())

    return app


def _json_error(codigo: int, mensaje: str) -> JSONResponse:
    return JSONResponse(status_code=codigo, content={"error": mensaje})


def _pagina_agente_corriendo() -> str:
    return (
        "<!doctype html><meta charset='utf-8'>"
        "<title>Agente SUNAT SOL</title>"
        "<body style=\"font-family:system-ui;max-width:40rem;margin:4rem auto;"
        "line-height:1.6;color:#141e2c\">"
        "<h1>El agente está corriendo</h1>"
        "<p>Esta ventana no es el panel. Ábrelo desde el ícono en la bandeja "
        "del sistema, o entra directo a la URL de tu panel.</p></body>"
    )


# --- token ------------------------------------------------------------------


def obtener_token(cfg: Config) -> str:
    """Token del agente, estable entre reinicios.

    Se guarda en la carpeta de datos del usuario para que el panel siga
    funcionando si reinicias el agente con la pestaña abierta.
    """
    archivo = cfg.data_dir / "agente.token"
    if archivo.exists():
        guardado = archivo.read_text(encoding="utf-8").strip()
        if guardado:
            return guardado

    token = secrets.token_urlsafe(32)
    archivo.parent.mkdir(parents=True, exist_ok=True)
    archivo.write_text(token, encoding="utf-8")
    try:
        archivo.chmod(0o600)
    except OSError:
        pass
    return token


# --- arranque ---------------------------------------------------------------


def preparar(cfg: Config | None = None) -> Config:
    """Deja la config lista para arrancar, sin todavía escuchar en ningún
    puerto.

    Separado de `iniciar()` porque el modo bandeja necesita este mismo
    trabajo —forzar navegador visible, configurar logging, limpiar perfiles
    viejos— antes de construir el servidor, pero no quiere el resto de
    `iniciar()` (que bloquea imprimiendo a consola).
    """
    cfg = cfg or cargar_config()
    # El agente siempre abre navegador visible: el sentido es que navegues tú.
    cfg = replace(cfg, headless=False)
    configurar(cfg)

    if (viejos := limpiar_perfiles_viejos(cfg)):
        _log.info("Limpiados perfiles del esquema anterior: %s", ", ".join(viejos))

    # Las instalaciones anteriores guardaron el token en texto plano. Se
    # protege al arrancar, una sola vez, sin pedirle nada al usuario.
    vinculacion.proteger_en_disco(cfg)

    return cfg


def crear_servidor(cfg: Config, puerto: int = PUERTO_POR_DEFECTO) -> "uvicorn.Server":
    """El servidor ya armado, sin arrancar todavía.

    Se expone como `uvicorn.Server` y no con `uvicorn.run()` porque el modo
    bandeja necesita un handle para apagarlo desde otro hilo —el del ícono—
    poniendo `servidor.should_exit = True`. `uvicorn.run()` no da eso: corre
    y bloquea hasta Ctrl+C, sin forma de pedirle que pare desde afuera.

    `log_config=None` es obligatorio en el `.exe` empaquetado. Por defecto,
    `uvicorn.Config` configura su propio logging con colores, y para
    decidir si el terminal los soporta llama `.isatty()` sobre
    `sys.stdout`/`sys.stderr`. El `.exe` se compila `--windowed`: cuando
    corre sin ninguna consola heredada (doble clic desde el Explorador,
    a diferencia de lanzarlo desde una terminal), esos dos son `None`, y
    `None.isatty()` revienta con
    `ValueError: Unable to configure formatter 'default'` —un mensaje que
    no menciona stdout ni colores en ningún lado. No hace falta el logging
    de uvicorn de todos modos: `agente.py` ya usa el logger propio de
    `log.py` para todo lo que importa.
    """
    import uvicorn

    token = obtener_token(cfg)
    app = crear_app(cfg, token, puerto)
    configuracion = uvicorn.Config(
        app, host=HOST, port=puerto, log_level="warning", log_config=None
    )
    return uvicorn.Server(configuracion)


def iniciar(cfg: Config | None = None, puerto: int = PUERTO_POR_DEFECTO) -> int:
    """Modo consola: arranca y bloquea hasta Ctrl+C.

    Es el modo de siempre, y sigue siendo el que usa `arranque.py` cuando la
    bandeja no está disponible (falta `pystray`, o `SUNAT_SIN_BANDEJA=1`).
    """
    cfg = preparar(cfg)
    servidor = crear_servidor(cfg, puerto)

    print()
    print(f"  Panel:      http://{HOST}:{puerto}")
    print(f"  Empresas:   {crear_repositorio(cfg).describir()}")
    print("  Ctrl+C para detener.")
    print()

    servidor.run()
    return 0
