"""Pruebas de la API del agente local.

No abren Chrome ni tocan SUNAT: el gestor de sesiones está sustituido por
un doble. Lo que más importa aquí son las guardas — token, `Origin` y
`Host` — porque el agente descifra credenciales y cualquier página que
visites puede intentar hablarle.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sunat.config import Config

fastapi = pytest.importorskip("fastapi", reason="Requiere el extra [web].")
from fastapi.testclient import TestClient  # noqa: E402

from sunat import agente as modulo_agente  # noqa: E402

TOKEN = "token-de-prueba"
PUERTO = 17817
ORIGEN = f"http://127.0.0.1:{PUERTO}"
CABECERAS = {"X-Agent-Token": TOKEN, "Origin": ORIGEN}


class GestorFalso:
    """Doble del gestor: registra qué se pidió abrir, sin abrir nada."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.abiertas_: list[tuple[str, str]] = []
        self.eventos = __import__("queue").Queue()

    def abierta(self, ruc, plataforma=None):
        destino = plataforma or "tramites"
        return (ruc, destino) in self.abiertas_

    def abiertas(self):
        return list(self.abiertas_)

    def rucs_abiertos(self):
        return sorted({r for r, _ in self.abiertas_})

    def abrir(self, empresa, clave, plataforma=None):
        assert clave, "hay que pasar la clave ya descifrada"
        destino = plataforma.id if plataforma is not None else "tramites"
        self.abiertas_.append((empresa.ruc, destino))
        return True


@pytest.fixture
def cliente(tmp_path, monkeypatch):
    monkeypatch.setattr(modulo_agente, "GestorSesiones", GestorFalso)
    cfg = replace(Config(data_dir=tmp_path), api_url="")
    app = modulo_agente.crear_app(cfg, TOKEN, PUERTO)
    # base_url real: si no, TestClient manda `Host: testserver` y la guarda
    # de Host lo rechaza con 403 antes de llegar a lo que se quiere probar.
    with TestClient(app, base_url=ORIGEN) as c:
        c.estado_agente = app.state.estado
        yield c


def desbloquear(cliente, password="maestra-de-prueba"):
    return cliente.post("/api/desbloquear", json={"password": password}, headers=CABECERAS)


# --- guardas ----------------------------------------------------------------




def test_rechaza_sin_token(cliente):
    r = cliente.get("/api/estado", headers={"Origin": ORIGEN})
    assert r.status_code == 401


def test_rechaza_token_incorrecto(cliente):
    r = cliente.get("/api/estado", headers={**CABECERAS, "X-Agent-Token": "otro"})
    assert r.status_code == 401


def test_rechaza_origen_ajeno(cliente):
    """El caso real: visitas una web y esa web llama a tu localhost."""
    r = cliente.get("/api/estado", headers={**CABECERAS, "Origin": "https://malicioso.com"})
    assert r.status_code == 403


def test_rechaza_host_ajeno(cliente):
    """Defensa contra DNS rebinding: un dominio que resuelve a 127.0.0.1."""
    r = cliente.get("/api/estado", headers={**CABECERAS, "Host": "rebind.malicioso.com"})
    assert r.status_code == 403


def test_acepta_sin_origen(cliente):
    """curl y el propio panel no siempre mandan Origin; eso no es sospechoso."""
    r = cliente.get("/api/estado", headers={"X-Agent-Token": TOKEN})
    assert r.status_code == 200


# --- bóveda -----------------------------------------------------------------


def test_arranca_bloqueada(cliente):
    r = cliente.get("/api/estado", headers=CABECERAS)
    assert r.json()["bloqueada"] is True
    assert r.json()["boveda_creada"] is False


def test_desbloquear_crea_la_boveda_la_primera_vez(cliente):
    r = desbloquear(cliente)
    assert r.status_code == 200
    assert r.json()["boveda_creada_ahora"] is True
    assert cliente.get("/api/estado", headers=CABECERAS).json()["bloqueada"] is False


def test_password_incorrecta_tras_crearla(cliente):
    desbloquear(cliente, "correcta-larga-de-prueba")
    cliente.post("/api/bloquear", headers=CABECERAS)
    r = desbloquear(cliente, "incorrecta-larga-de-prueba")
    assert r.status_code == 400
    assert "incorrecta" in r.json()["error"].lower()


def test_bloquear(cliente):
    desbloquear(cliente)
    cliente.post("/api/bloquear", headers=CABECERAS)
    assert cliente.get("/api/estado", headers=CABECERAS).json()["bloqueada"] is True


def test_operar_bloqueada_devuelve_423(cliente):
    r = cliente.get("/api/empresas", headers=CABECERAS)
    assert r.status_code == 423


# --- empresas ---------------------------------------------------------------


def guardar(cliente, ruc="20111111111", nombre="Matto", usuario="USR", clave="claveSOL"):
    return cliente.put(
        f"/api/empresas/{ruc}",
        json={"nombre": nombre, "ruc": ruc, "usuario": usuario, "clave": clave},
        headers=CABECERAS,
    )


def test_crear_y_listar(cliente):
    desbloquear(cliente)
    assert guardar(cliente).status_code == 200

    empresas = cliente.get("/api/empresas", headers=CABECERAS).json()
    assert len(empresas) == 1
    assert empresas[0]["ruc"] == "20111111111"
    assert empresas[0]["abiertas"] == []


def test_el_listado_nunca_incluye_la_clave(cliente):
    """El panel no necesita la clave y no debe recibirla, ni cifrada."""
    desbloquear(cliente)
    guardar(cliente, clave="claveSOLsecreta")

    crudo = cliente.get("/api/empresas", headers=CABECERAS).text
    assert "claveSOLsecreta" not in crudo
    assert "clave" not in crudo


def test_editar_sin_clave_conserva_la_anterior(cliente):
    desbloquear(cliente)
    guardar(cliente, clave="original")
    guardar(cliente, nombre="Nombre Nuevo", clave="")

    vault = cliente.estado_agente.vault
    empresa = vault.obtener("20111111111")
    assert empresa.nombre == "Nombre Nuevo"
    assert vault.clave_de(empresa) == "original"


def test_empresa_nueva_sin_clave_se_rechaza(cliente):
    desbloquear(cliente)
    r = guardar(cliente, ruc="20999999999", clave="")
    assert r.status_code == 400


def test_ruc_invalido_se_rechaza(cliente):
    desbloquear(cliente)
    r = cliente.put(
        "/api/empresas/123",
        json={"nombre": "X", "ruc": "123", "usuario": "U", "clave": "c"},
        headers=CABECERAS,
    )
    assert r.status_code == 422


def test_ruc_de_ruta_y_cuerpo_deben_coincidir(cliente):
    desbloquear(cliente)
    r = cliente.put(
        "/api/empresas/20111111111",
        json={"nombre": "X", "ruc": "20222222222", "usuario": "U", "clave": "c"},
        headers=CABECERAS,
    )
    assert r.status_code == 400


def test_eliminar(cliente):
    desbloquear(cliente)
    guardar(cliente)
    assert cliente.delete("/api/empresas/20111111111", headers=CABECERAS).status_code == 200
    assert cliente.get("/api/empresas", headers=CABECERAS).json() == []


# --- sesiones ---------------------------------------------------------------


def test_abrir_sesion_descifra_y_delega(cliente):
    desbloquear(cliente)
    guardar(cliente)

    r = cliente.post("/api/sesiones", json={"ruc": "20111111111"}, headers=CABECERAS)
    assert r.json()["ok"] is True
    assert cliente.estado_agente.gestor.abiertas_ == [("20111111111", "tramites")]


def test_no_abre_dos_veces(cliente):
    desbloquear(cliente)
    guardar(cliente)
    cliente.post("/api/sesiones", json={"ruc": "20111111111"}, headers=CABECERAS)
    r = cliente.post("/api/sesiones", json={"ruc": "20111111111"}, headers=CABECERAS)

    assert r.json()["ok"] is False
    assert cliente.estado_agente.gestor.abiertas_ == [("20111111111", "tramites")]


def test_abrir_empresa_inexistente(cliente):
    desbloquear(cliente)
    r = cliente.post("/api/sesiones", json={"ruc": "20999999999"}, headers=CABECERAS)
    assert r.status_code == 400


# --- panel ------------------------------------------------------------------


def test_el_panel_recibe_el_token_inyectado(cliente, tmp_path, monkeypatch):
    """El token llega en el HTML: nunca hay que copiarlo a mano."""
    r = cliente.get("/", headers={"Host": f"127.0.0.1:{PUERTO}"})
    assert r.status_code == 200
    # Sin build, sirve la página de ayuda; con build, el token va dentro.
    assert "__TOKEN_AGENTE__" not in r.text


def test_assets_no_permite_salir_del_directorio(cliente):
    r = cliente.get("/assets/../../../../Windows/win.ini", headers=CABECERAS)
    assert r.status_code == 404


# --- plataformas ------------------------------------------------------------


def test_el_estado_publica_el_catalogo_de_plataformas(cliente):
    """El panel dibuja el menú de destinos con esto: agregar una plataforma
    no debe obligar a tocar el frontend."""
    datos = cliente.get("/api/estado", headers=CABECERAS).json()
    ids = [p["id"] for p in datos["plataformas"]]
    assert {"tramites", "declaraciones"} <= set(ids)
    assert datos["plataforma_por_defecto"] in ids


def test_ingresar_sin_plataforma_usa_la_de_por_defecto(cliente):
    desbloquear(cliente)
    guardar(cliente)
    r = cliente.post("/api/sesiones", json={"ruc": "20111111111"}, headers=CABECERAS)

    assert r.json()["plataforma"] == "tramites"
    assert cliente.estado_agente.gestor.abiertas_ == [("20111111111", "tramites")]


def test_ingresar_a_declaraciones(cliente):
    desbloquear(cliente)
    guardar(cliente)
    r = cliente.post(
        "/api/sesiones",
        json={"ruc": "20111111111", "plataforma": "declaraciones"},
        headers=CABECERAS,
    )

    assert r.json()["ok"] is True
    assert cliente.estado_agente.gestor.abiertas_ == [("20111111111", "declaraciones")]


def test_la_misma_empresa_puede_estar_en_las_dos_a_la_vez(cliente):
    """El caso de uso: consultar el buzón mientras declaras."""
    desbloquear(cliente)
    guardar(cliente)
    for pf in ("tramites", "declaraciones"):
        cliente.post(
            "/api/sesiones",
            json={"ruc": "20111111111", "plataforma": pf},
            headers=CABECERAS,
        )

    assert cliente.estado_agente.gestor.abiertas_ == [
        ("20111111111", "tramites"),
        ("20111111111", "declaraciones"),
    ]


def test_no_abre_dos_veces_la_misma_plataforma(cliente):
    desbloquear(cliente)
    guardar(cliente)
    cuerpo = {"ruc": "20111111111", "plataforma": "declaraciones"}
    cliente.post("/api/sesiones", json=cuerpo, headers=CABECERAS)
    r = cliente.post("/api/sesiones", json=cuerpo, headers=CABECERAS)

    assert r.json()["ok"] is False
    assert len(cliente.estado_agente.gestor.abiertas_) == 1


def test_plataforma_inventada_se_rechaza(cliente):
    desbloquear(cliente)
    guardar(cliente)
    r = cliente.post(
        "/api/sesiones",
        json={"ruc": "20111111111", "plataforma": "inventada"},
        headers=CABECERAS,
    )
    assert r.status_code == 400


def test_el_listado_dice_en_que_plataformas_esta_abierta(cliente):
    desbloquear(cliente)
    guardar(cliente)
    cliente.post(
        "/api/sesiones",
        json={"ruc": "20111111111", "plataforma": "declaraciones"},
        headers=CABECERAS,
    )

    empresas = cliente.get("/api/empresas", headers=CABECERAS).json()
    assert empresas[0]["abiertas"] == ["declaraciones"]
