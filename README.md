# Agente local — SUNAT Launcher

Guarda las claves SOL de una empresa cifradas, y con un clic abre Chrome ya
autenticado en SUNAT. Es la pieza que corre en la computadora del usuario,
no en la nube: es quien cifra, descifra y abre el navegador, para que el
backend nunca vea una clave SOL en claro ni la contraseña maestra.

Este repo es solo el agente. El panel web y el backend que lo acompañan
viven en otros repos — este componente funciona solo (arranca, sirve su
API en `127.0.0.1:17817`), pero solo es *útil* junto a un panel que sepa
hablarle con el mismo contrato (ver «Protocolo con el panel» abajo).

---

## Guía rápida

### Si vas a desarrollar sobre esto

```bash
python -m venv venv
venv\Scripts\activate
pip install -e ".[dev]"
playwright install chromium   # una sola vez; se cachea por usuario

python -m sunat
```

Queda escuchando en `http://127.0.0.1:17817`. Corre `pytest` para las 128
pruebas (ninguna toca la red ni SUNAT).

### Si solo vas a usarlo (sin tocar código)

No clones este repo: descarga el `.exe` ya compilado desde
**[Releases](../../releases/latest)**, descomprime el `.zip` y ejecuta
`sunat-agente.exe`. Windows puede avisar "Editor desconocido" la primera
vez — normal mientras el `.exe` no esté firmado (ver «Pendiente» abajo).

### Si vas a publicar una versión nueva

```bash
git tag v1.0.0
git push origin v1.0.0
```

Un tag `v*` dispara [`.github/workflows/build.yml`](.github/workflows/build.yml):
compila en un runner de Windows, empaqueta `dist/sunat-agente/` en
`sunat-agente-windows.zip`, y lo publica como el último Release. También se
puede lanzar a mano desde la pestaña *Actions*, sin tag, para probar el
pipeline antes de versionar de verdad.

---

## Por qué existe un agente aparte

Si el panel hablara directo con la base de datos, tendría que reimplementar
scrypt y Fernet en JavaScript. Dos implementaciones que difieran en un
detalle producen claves que después no se pueden descifrar — y no lo
notarías hasta necesitarlas. Con el agente en medio hay **una sola**
implementación del cifrado, la que está probada en `tests/`.

Consecuencia deliberada: ni la contraseña maestra ni una clave SOL en claro
salen jamás de `127.0.0.1`. Si el backend que lo acompaña se filtra un día,
lo que se lleva el atacante son bytes cifrados que, sin la contraseña
maestra del usuario, no sirven de nada.

## Protocolo con el panel

Dos identidades distintas, ambas necesarias:

**El token del agente** — lo entrega `GET /api/handshake`, la única ruta
sin autenticación (no podría exigirla: es la que la entrega). Lo protege
la guarda de `Origin`/`Host`: el agente solo responde a los orígenes
listados en `PANEL_ORIGENES` de [`config.py`](src/sunat/config.py) —por
defecto `127.0.0.1:5173` y `localhost:5173` para desarrollo, más lo que se
agregue con `SUNAT_PANEL_ORIGENES` en producción— y su cabecera CORS impide
que cualquier otra página lea la respuesta.

**El token de dispositivo** — lo emite el backend para la cuenta del
usuario, y es lo que el agente usa para leer y guardar sus empresas. El
panel se lo entrega al agente vía `POST /api/vincular`, junto con la URL
del backend; queda guardado en
`%LOCALAPPDATA%\sunat-launcher\device.json`, y es revocable desde el panel
sin tocar otras computadoras del mismo usuario. `validar_api_url()` en
[`vinculacion.py`](src/sunat/vinculacion.py) rechaza vincularlo contra un
backend por HTTP plano fuera de `localhost` — sin eso, una página del
origen permitido podría redirigir el token a un servidor propio.

## Rutas de la API

```
GET    /api/handshake      token del agente. Sin auth — protegida por Origin/Host.
POST   /api/vincular       guarda el token de dispositivo + URL del backend
POST   /api/desvincular    olvida la vinculación local (no revoca en el backend)
GET    /api/estado         bloqueada | boveda_creada | vinculado | sesiones abiertas
POST   /api/desbloquear    abre la bóveda con la contraseña maestra (o la crea)
POST   /api/bloquear
GET    /api/empresas
PUT    /api/empresas/{ruc}
DELETE /api/empresas/{ruc}
POST   /api/sesiones       abre Chrome autenticado para un RUC + plataforma
GET    /api/eventos        SSE: progreso de las sesiones que se van abriendo
```

Todas menos `handshake` exigen `X-Agent-Token` (el del agente, no el de
dispositivo).

## Estructura

```
src/sunat/
├─ __main__.py        punto de entrada: python -m sunat
├─ arranque.py         primer arranque: fija PLAYWRIGHT_BROWSERS_PATH,
│                       descarga Chromium si falta, delega a agente.iniciar()
├─ agente.py            la API FastAPI que consume el panel
├─ vinculacion.py       token de esta computadora: guardar, leer, validar destino
├─ config.py            rutas, orígenes del panel, todo por variable de entorno
├─ crypto.py            scrypt -> Fernet. Cifra; no sabe dónde se guarda.
├─ store.py             une crypto + repositorios
├─ repositorios.py      dónde se guarda: vía el backend, o un archivo local
├─ auth.py              login en SUNAT + clasificación de fallos + reintentos
├─ browser.py           ciclo de vida de Chromium
├─ sesiones.py          un navegador por hilo + cola de eventos
├─ navigation.py        iframes y ventanas del menú SOL
├─ selectors.py         todos los selectores del portal
├─ plataformas.py       trámites | declaraciones
└─ log.py               archivo rotativo + consola
packaging/
├─ build.py             compila el .exe (ver Guía rápida)
├─ lanzador.py           entrypoint que usa PyInstaller
└─ diagnostico_chromium.py  prueba aislada: ¿arranca Chromium dentro del .exe?
tests/                 128 pruebas, ninguna toca la red
```

## El instalador de un clic

Nadie fuera de este repo debería ver `pip install` ni una terminal. Lo que
se distribuye es un `.exe` autocontenido — ver «Guía rápida» arriba para
compilarlo, y «Cómo se distribuye» para publicarlo.

Se deja la consola visible a propósito: si algo falla, ahí se ve el error.
Una versión sin consola es más prolija, pero si falla no muestra nada —
para eso hace falta antes tener logs y manejo de errores más maduros de los
que hay hoy.

### Qué resolvió `packaging/build.py` que no era obvio

**Playwright no busca el navegador donde uno espera dentro de un `.exe`
congelado.** Un `.exe` de PyInstaller cuenta como instalación "no
estándar", y en ese caso Playwright busca el navegador junto al propio
paquete empaquetado en vez de en la caché compartida del usuario
(`%LOCALAPPDATA%\ms-playwright`). El síntoma es
`Executable doesn't exist at ...\_internal\playwright\driver\...` incluso
con Chromium ya descargado — lo buscó en el lugar equivocado, no es que
falte. Se resuelve fijando `PLAYWRIGHT_BROWSERS_PATH` explícitamente en
[`arranque.py`](src/sunat/arranque.py), antes de que cualquier otro módulo
importe Playwright. Cubierto por
[`tests/test_arranque.py`](tests/test_arranque.py); verificado además con
un `.exe` real vía
[`packaging/diagnostico_chromium.py`](packaging/diagnostico_chromium.py),
que lanza Chromium sin depender del resto del agente — útil si esto vuelve
a romperse en una versión futura de Playwright o PyInstaller.

### Cómo se distribuye: GitHub Releases

El panel apunta a
`https://github.com/<owner>/<repo>/releases/latest/download/sunat-agente-windows.zip`
— esa URL **siempre** resuelve al último Release con ese nombre de archivo,
así que el panel no necesita saber el número de versión. Se configura en
el `.env` del panel como `VITE_AGENT_DOWNLOAD_URL`; sin ella, el banner de
«instala el agente» no muestra botón de descarga.

### Pendiente, sin resolver todavía

- **Firma de código.** Sin firmar, Windows SmartScreen va a advertir "Editor
  desconocido" en el primer uso. No bloquea la instalación, pero asusta. La
  opción más completa es [Azure Trusted
  Signing](https://learn.microsoft.com/azure/trusted-signing/overview):
  reputación de SmartScreen inmediata, sin token USB, integrable en el
  workflow de arriba con la Action `azure/trusted-signing-action` — el
  lugar exacto está marcado con un comentario en el `.yml`. Requiere
  verificación de identidad (persona o negocio) que solo el dueño del
  proyecto puede completar, así que queda sin automatizar hasta que se
  decida.
- **Verificar `/api/sesiones` (abrir Chrome) desde el `.exe` en un
  escritorio real.** El handshake, la vinculación y el guardado de
  empresas están probados de punta a punta contra un backend real. Abrir
  una sesión de verdad —lanzar Chrome visible y navegar a SUNAT— **no** se
  probó automatizado: hacerlo hubiera significado un intento de login real
  contra SUNAT con credenciales falsas, algo que este proyecto advierte
  evitar. Pruébalo a mano, una vez, desde tu escritorio.
- Auto-actualización: hoy cada versión nueva es descargar el `.exe` de
  nuevo a mano.

## Tests

```bash
pytest
```

Cubren lo que duele si se rompe: que el vault no se pueda leer con la
contraseña equivocada, que un login rechazado no se reintente, que el
token de esta computadora no salga hacia un origen que el agente no
reconoce, ni hacia un backend por HTTP plano fuera de localhost.

## Configuración

Nada de esto hace falta para el caso normal — el panel vincula el agente
al primer uso. `.env.example` lista lo ajustable: orígenes del panel en
producción (`SUNAT_PANEL_ORIGENES`), modo headless, nivel de log, y el
modo anterior de una sola llave compartida (`SUNAT_API_URL` /
`SUNAT_API_KEY`), que la vinculación por panel reemplaza pero no rompe si
ya lo tenías configurado así.
