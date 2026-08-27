"""Protección del token de dispositivo en disco (DPAPI).

Lo que se cuida aquí es el primer eslabón del ataque que más importa: un
programa cualquiera corriendo con la sesión del usuario leyendo
`device.json`, pidiendo con ese token la cabecera de la bóveda y todas las
claves cifradas, y atacando la contraseña maestra sin conexión.

Con el token protegido, el archivo suelto —un respaldo, una carpeta
sincronizada, un disco robado— deja de servir.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from sunat import proteccion, vinculacion
from sunat.config import Config

TOKEN = "sla_" + "a" * 64
BACKEND = "https://api.ejemplo.com"

soloWindows = pytest.mark.skipif(
    not proteccion.disponible(), reason="DPAPI solo existe en Windows."
)


@pytest.fixture
def cfg(tmp_path):
    return replace(
        Config(data_dir=tmp_path),
        api_url="",
        api_key="",
        backends_extra=BACKEND,
    )


def crudo(cfg) -> dict:
    """El JSON tal como quedó en disco, sin pasar por `leer`."""
    return json.loads(vinculacion.ruta(cfg).read_text(encoding="utf-8"))


# --- la primitiva -----------------------------------------------------------


@soloWindows
def test_ida_y_vuelta():
    protegido = proteccion.proteger(TOKEN)
    assert proteccion.esta_protegido(protegido)
    assert proteccion.desproteger(protegido) == TOKEN


@soloWindows
def test_el_texto_plano_no_aparece_en_el_resultado():
    assert TOKEN not in proteccion.proteger(TOKEN)


@soloWindows
def test_un_blob_de_otra_aplicacion_no_se_acepta(monkeypatch):
    """La entropía ata el blob a este programa.

    Sin ella, un blob DPAPI producido por cualquier otra aplicación del mismo
    usuario se podría pegar dentro de device.json.
    """
    protegido = proteccion.proteger(TOKEN)

    monkeypatch.setattr(proteccion, "_ENTROPIA", b"otra-aplicacion")
    with pytest.raises(proteccion.ProteccionFallida):
        proteccion.desproteger(protegido)


@soloWindows
def test_un_blob_corrupto_no_revienta_de_cualquier_forma():
    with pytest.raises(proteccion.ProteccionFallida):
        proteccion.desproteger(proteccion.MARCA + "esto no es base64!!")


def test_un_valor_sin_marca_pasa_tal_cual():
    """Es lo que permite leer los device.json escritos antes de esto."""
    assert proteccion.desproteger(TOKEN) == TOKEN
    assert not proteccion.esta_protegido(TOKEN)


# --- integrado en la vinculación --------------------------------------------


@soloWindows
def test_guardar_no_deja_el_token_en_claro(cfg):
    vinculacion.guardar(cfg, TOKEN, BACKEND)

    assert TOKEN not in json.dumps(crudo(cfg))
    assert proteccion.esta_protegido(crudo(cfg)["token"])
    assert vinculacion.leer(cfg).token == TOKEN


def test_un_device_json_anterior_se_sigue_leyendo(cfg):
    """Actualizar el agente no puede desvincular a nadie."""
    vinculacion.ruta(cfg).parent.mkdir(parents=True, exist_ok=True)
    vinculacion.ruta(cfg).write_text(
        json.dumps({"version": 1, "token": TOKEN, "api_url": BACKEND}),
        encoding="utf-8",
    )

    assert vinculacion.leer(cfg).token == TOKEN


@soloWindows
def test_un_device_json_anterior_se_migra_al_arrancar(cfg):
    vinculacion.ruta(cfg).parent.mkdir(parents=True, exist_ok=True)
    vinculacion.ruta(cfg).write_text(
        json.dumps({"version": 1, "token": TOKEN, "api_url": BACKEND}),
        encoding="utf-8",
    )

    assert vinculacion.proteger_en_disco(cfg) is True
    assert proteccion.esta_protegido(crudo(cfg)["token"])
    assert vinculacion.leer(cfg).token == TOKEN

    # Idempotente: el segundo arranque no tiene nada que hacer.
    assert vinculacion.proteger_en_disco(cfg) is False


@soloWindows
def test_un_archivo_de_otra_maquina_se_trata_como_no_vinculado(cfg):
    """El caso real: un respaldo restaurado o un perfil migrado.

    DPAPI ata el dato a esta cuenta de Windows, así que el blob no descifra.
    Se responde "no vinculado" —el usuario vuelve a vincular en dos clics— y
    no con un error que lo deje sin saber qué hacer.
    """
    vinculacion.ruta(cfg).parent.mkdir(parents=True, exist_ok=True)
    vinculacion.ruta(cfg).write_text(
        json.dumps(
            {
                "version": 1,
                "token": proteccion.MARCA + "AQAAANCMnd8BFdERjHoAwE/Cl+sAAAAA",
                "api_url": BACKEND,
            }
        ),
        encoding="utf-8",
    )

    assert vinculacion.leer(cfg) is None
