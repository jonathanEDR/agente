"""Pruebas de la vinculación del agente con una cuenta del SaaS.

Lo que se cuida aquí es que el token de esta computadora no acabe en manos
de otra página ni viajando a un servidor que no es el nuestro. La ruta
`/api/handshake` es la única sin token, así que su guarda de procedencia es
lo único que la separa de cualquier sitio que el usuario visite.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from sunat import vinculacion
from sunat.config import Config, crear_repositorio
from sunat.repositorios import RepositorioApi, RepositorioArchivo
from sunat.vinculacion import VinculacionInvalida

fastapi = pytest.importorskip("fastapi", reason="Requiere el extra [web].")
from fastapi.testclient import TestClient  # noqa: E402

from sunat import agente as modulo_agente  # noqa: E402

TOKEN = "token-de-prueba"
PUERTO = 17817
ORIGEN_AGENTE = f"http://127.0.0.1:{PUERTO}"
ORIGEN_PANEL = "http://127.0.0.1:5173"
CABECERAS = {"X-Agent-Token": TOKEN, "Origin": ORIGEN_PANEL}

TOKEN_DISPOSITIVO = "sla_" + "a" * 64


class GestorFalso:
    """El agente construye uno al arrancar; aquí no abre nada."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.eventos = __import__("queue").Queue()

    def abierta(self, ruc, plataforma=None):
        return False

    def abiertas(self):
        return []

    def rucs_abiertos(self):
        return []


# Backends que estos tests dan por buenos. Van por `backends_extra` —la
# variable de entorno— porque es justo el mecanismo previsto para ambientes
# que no son produccion, y asi los tests ejercitan el camino real en vez de
# esquivar la lista blanca.
BACKENDS_DE_PRUEBA = ",".join(
    [
        "https://api.ejemplo.com",
        "https://nueva.ejemplo.com",
        "https://vieja.ejemplo.com",
    ]
)


@pytest.fixture
def cfg(tmp_path):
    return replace(
        Config(data_dir=tmp_path),
        api_url="",
        api_key="",
        backends_extra=BACKENDS_DE_PRUEBA,
    )


@pytest.fixture
def cliente(cfg, monkeypatch):
    monkeypatch.setattr(modulo_agente, "GestorSesiones", GestorFalso)
    app = modulo_agente.crear_app(cfg, TOKEN, PUERTO)
    # base_url real: con `Host: testserver` la guarda de Host responde 403
    # antes de llegar a lo que se quiere probar.
    with TestClient(app, base_url=ORIGEN_AGENTE) as c:
        c.estado_agente = app.state.estado
        yield c


# --- a qué backend se deja apuntar el token ---------------------------------


PERMITIDOS = ["https://api.ejemplo.com", "http://127.0.0.1:4000"]


def test_exige_https_fuera_de_localhost():
    with pytest.raises(VinculacionInvalida):
        vinculacion.validar_api_url("http://api.ejemplo.com", PERMITIDOS)


def test_acepta_un_backend_de_la_lista():
    assert vinculacion.validar_api_url("https://api.ejemplo.com/", PERMITIDOS) == (
        "https://api.ejemplo.com"
    )


def test_acepta_http_solo_en_localhost():
    assert (
        vinculacion.validar_api_url("http://127.0.0.1:4000", PERMITIDOS)
        == "http://127.0.0.1:4000"
    )


def test_rechaza_esquemas_raros():
    for url in ["file:///etc/passwd", "ftp://ejemplo.com", ""]:
        with pytest.raises(VinculacionInvalida):
            vinculacion.validar_api_url(url, PERMITIDOS)


# --- la lista blanca --------------------------------------------------------
#
# Lo que se cuida aqui es el escenario de A2: un script en el panel llamando a
# /api/vincular con un backend suyo. Antes bastaba que fuera https.


def test_rechaza_un_backend_que_no_esta_en_la_lista():
    with pytest.raises(VinculacionInvalida):
        vinculacion.validar_api_url("https://servidor-del-atacante.com", PERMITIDOS)


def test_rechaza_el_truco_del_arroba():
    """`https://backend-real@evil.com` tiene como host a evil.com.

    Comparar la cadena tal como llego lo daria por bueno; por eso se compara
    el origen reconstruido.
    """
    with pytest.raises(VinculacionInvalida):
        vinculacion.validar_api_url("https://api.ejemplo.com@evil.com", PERMITIDOS)


def test_rechaza_un_subdominio_que_solo_se_parece():
    with pytest.raises(VinculacionInvalida):
        vinculacion.validar_api_url("https://api.ejemplo.com.evil.com", PERMITIDOS)


def test_rechaza_una_url_con_ruta():
    with pytest.raises(VinculacionInvalida):
        vinculacion.validar_api_url("https://api.ejemplo.com/api", PERMITIDOS)


def test_guardar_rechaza_un_backend_de_fuera(cfg):
    """La lista llega desde la config, no como argumento suelto."""
    with pytest.raises(VinculacionInvalida):
        vinculacion.guardar(cfg, TOKEN_DISPOSITIVO, "https://servidor-del-atacante.com")

    assert vinculacion.leer(cfg) is None


def test_el_backend_del_producto_esta_permitido():
    from sunat.config import BACKENDS_PERMITIDOS

    cfg_limpia = Config()
    for backend in BACKENDS_PERMITIDOS:
        assert vinculacion.validar_api_url(backend, cfg_limpia.backends_permitidos())


# --- guardar y leer ---------------------------------------------------------


def test_sin_vincular_no_hay_nada(cfg):
    assert vinculacion.leer(cfg) is None


def test_guardar_y_leer(cfg):
    vinculacion.guardar(cfg, TOKEN_DISPOSITIVO, "https://api.ejemplo.com")

    leido = vinculacion.leer(cfg)
    assert leido is not None
    assert leido.token == TOKEN_DISPOSITIVO
    assert leido.api_url == "https://api.ejemplo.com"


def test_un_archivo_ilegible_se_trata_como_no_vinculado(cfg):
    # Más útil que un error: el usuario puede volver a vincular desde el
    # panel sin tener que borrar nada a mano.
    vinculacion.ruta(cfg).write_text("{ esto no es json", encoding="utf-8")
    assert vinculacion.leer(cfg) is None


def test_un_archivo_sin_token_se_trata_como_no_vinculado(cfg):
    vinculacion.ruta(cfg).write_text(
        json.dumps({"version": 1, "api_url": "https://api.ejemplo.com"}),
        encoding="utf-8",
    )
    assert vinculacion.leer(cfg) is None


def test_olvidar(cfg):
    vinculacion.guardar(cfg, TOKEN_DISPOSITIVO, "https://api.ejemplo.com")
    assert vinculacion.olvidar(cfg) is True
    assert vinculacion.leer(cfg) is None
    assert vinculacion.olvidar(cfg) is False


def test_no_se_guarda_en_la_carpeta_del_proyecto(cfg, tmp_path):
    vinculacion.guardar(cfg, TOKEN_DISPOSITIVO, "https://api.ejemplo.com")
    assert vinculacion.ruta(cfg).parent == tmp_path


# --- qué repositorio sale de la configuración -------------------------------


def test_sin_vinculo_ni_env_usa_el_archivo(cfg):
    assert isinstance(crear_repositorio(cfg), RepositorioArchivo)


def test_el_vinculo_gana_sobre_las_variables_de_entorno(cfg):
    # SUNAT_API_URL es el modo anterior, de una sola llave compartida. Si el
    # usuario vinculó desde el panel, eso es lo que eligió.
    con_env = replace(cfg, api_url="https://vieja.ejemplo.com", api_key="llave-vieja")
    vinculacion.guardar(con_env, TOKEN_DISPOSITIVO, "https://nueva.ejemplo.com")

    repo = crear_repositorio(con_env)
    assert isinstance(repo, RepositorioApi)
    assert repo.base_url == "https://nueva.ejemplo.com"
    assert repo.token == TOKEN_DISPOSITIVO


def test_sin_vinculo_las_variables_de_entorno_siguen_valiendo(cfg):
    con_env = replace(cfg, api_url="https://vieja.ejemplo.com", api_key="llave-vieja")
    repo = crear_repositorio(con_env)
    assert isinstance(repo, RepositorioApi)
    assert repo.base_url == "https://vieja.ejemplo.com"


# --- handshake: la única ruta sin token -------------------------------------


def test_handshake_entrega_el_token_al_panel(cliente):
    r = cliente.get("/api/handshake", headers={"Origin": ORIGEN_PANEL})
    assert r.status_code == 200

    datos = r.json()
    assert datos["token"] == TOKEN
    assert datos["vinculado"] is False


def test_handshake_rechaza_una_pagina_cualquiera(cliente):
    # Sin esto, cualquier sitio que visites se lleva el token del agente y
    # con él puede descifrar y abrir sesiones.
    r = cliente.get("/api/handshake", headers={"Origin": "https://sitio-malicioso.com"})
    assert r.status_code == 403


def test_handshake_rechaza_host_ajeno(cliente):
    # DNS rebinding: un dominio que resuelva a 127.0.0.1 llega con su Host.
    r = cliente.get(
        "/api/handshake",
        headers={"Origin": ORIGEN_PANEL, "Host": "atacante.com"},
    )
    assert r.status_code == 403


def test_el_panel_puede_leer_la_respuesta(cliente):
    # Sin la cabecera de CORS el navegador descarta la respuesta aunque el
    # agente la haya devuelto, y el panel no puede hablarle nunca.
    r = cliente.get("/api/handshake", headers={"Origin": ORIGEN_PANEL})
    assert r.headers.get("access-control-allow-origin") == ORIGEN_PANEL


def test_el_panel_de_produccion_esta_permitido_por_defecto(cliente):
    # El .exe se distribuye a usuarios sin conocimientos tecnicos: no van a
    # configurar SUNAT_PANEL_ORIGENES a mano. El dominio real tiene que
    # funcionar sin que nadie toque una variable de entorno.
    origen_produccion = "https://conta-beta-puce.vercel.app"
    r = cliente.get("/api/handshake", headers={"Origin": origen_produccion})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == origen_produccion


def test_el_preflight_del_panel_pasa(cliente):
    # El preflight va sin token: si lo contestara la guarda de procedencia
    # en vez de CORS, ninguna llamada del panel llegaría al agente.
    r = cliente.options(
        "/api/estado",
        headers={
            "Origin": ORIGEN_PANEL,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-agent-token",
        },
    )
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == ORIGEN_PANEL


# --- vincular ---------------------------------------------------------------


def test_vincular_exige_el_token_del_agente(cliente):
    r = cliente.post(
        "/api/vincular",
        json={"token": TOKEN_DISPOSITIVO, "api_url": "http://127.0.0.1:4000"},
        headers={"Origin": ORIGEN_PANEL},
    )
    assert r.status_code == 401


def test_vincular_rechaza_un_backend_por_http_remoto(cliente, cfg):
    r = cliente.post(
        "/api/vincular",
        json={"token": TOKEN_DISPOSITIVO, "api_url": "http://api-del-atacante.com"},
        headers=CABECERAS,
    )
    assert r.status_code == 400
    assert vinculacion.leer(cfg) is None


def test_vincular_contra_un_backend_caido_no_deja_rastro(cliente, cfg):
    # Puerto cerrado: la comprobacion inmediata falla y hay que revertir. Si
    # no, el usuario queda "vinculado" y el fallo aparece recien en la
    # primera accion real, donde ya no es evidente cual fue la causa.
    r = cliente.post(
        "/api/vincular",
        json={"token": TOKEN_DISPOSITIVO, "api_url": "http://127.0.0.1:1"},
        headers=CABECERAS,
    )
    assert r.status_code == 400
    assert vinculacion.leer(cfg) is None


def test_desvincular_bloquea_la_boveda(cliente, cfg):
    # La bóveda abierta se derivó del salt del almacenamiento anterior:
    # contra el nuevo no descifra nada, así que dejarla abierta es mentir.
    cliente.post("/api/desbloquear", json={"password": "maestra-de-prueba"}, headers=CABECERAS)
    assert cliente.estado_agente.bloqueada is False

    r = cliente.post("/api/desvincular", headers=CABECERAS)
    assert r.status_code == 200
    assert cliente.estado_agente.bloqueada is True


def test_el_estado_dice_si_esta_vinculado(cliente, cfg):
    assert cliente.get("/api/estado", headers=CABECERAS).json()["vinculado"] is False

    vinculacion.guardar(cfg, TOKEN_DISPOSITIVO, "https://api.ejemplo.com")
    assert cliente.get("/api/estado", headers=CABECERAS).json()["vinculado"] is True
