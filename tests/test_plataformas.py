"""Pruebas del catálogo de plataformas y del aislamiento entre ellas.

La idea que sostienen estos tests: la plataforma es propiedad de la SESIÓN,
no de la empresa. Las credenciales son las mismas en todas; lo único que
cambia es a qué portal de SUNAT se entra.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sunat import plataformas
from sunat.config import Config


def test_hay_al_menos_las_dos_conocidas():
    assert {"tramites", "declaraciones"} <= set(plataformas.ids())


def test_cada_plataforma_tiene_su_propia_url():
    urls = [p.url_entrada for p in plataformas.TODAS]
    assert len(urls) == len(set(urls)), "dos plataformas apuntando al mismo sitio"


def test_todas_entran_por_e_menu():
    # Verificado en vivo: ambas redirigen solas al formulario en
    # api-seguridad, cada una con su client_id. Entrar por e-menu evita
    # hardcodear esos client_id, que sí pueden cambiar.
    for p in plataformas.TODAS:
        assert p.url_entrada.startswith("https://e-menu.sunat.gob.pe/")


def test_obtener_sin_id_devuelve_la_de_por_defecto():
    assert plataformas.obtener(None) is plataformas.POR_DEFECTO
    assert plataformas.obtener("") is plataformas.POR_DEFECTO


def test_obtener_por_id():
    assert plataformas.obtener("declaraciones") is plataformas.DECLARACIONES


def test_obtener_id_desconocido_explica_las_validas():
    with pytest.raises(ValueError) as e:
        plataformas.obtener("inventada")
    assert "tramites" in str(e.value)


# --- aislamiento de perfiles ------------------------------------------------


def test_cada_plataforma_usa_su_propio_perfil(tmp_path):
    """Sin esto, las dos sesiones del mismo RUC compartirían cookies."""
    cfg = replace(Config(data_dir=tmp_path))
    a = cfg.perfil_de("20111111111", "tramites")
    b = cfg.perfil_de("20111111111", "declaraciones")
    assert a != b


def test_el_perfil_pone_la_plataforma_primero(tmp_path):
    """Con <RUC>/<plataforma>, quien ya tenía un perfil del esquema anterior
    en profiles/<RUC>/ acababa con un perfil de Chrome dentro de otro perfil
    de Chrome. Con la plataforma arriba, ese nivel es siempre contenedor."""
    cfg = replace(Config(data_dir=tmp_path))
    perfil = cfg.perfil_de("20111111111", "declaraciones")
    assert perfil.parent.name == "declaraciones"
    assert perfil.name == "20111111111"


def test_ningun_perfil_queda_dentro_de_otro(tmp_path):
    cfg = replace(Config(data_dir=tmp_path))
    rutas = [
        cfg.perfil_de(ruc, pf.id)
        for ruc in ("20111111111", "20222222222")
        for pf in plataformas.TODAS
    ]
    for a in rutas:
        for b in rutas:
            if a != b:
                assert b not in a.parents, f"{b} contiene a {a}"


def test_detecta_los_perfiles_del_esquema_viejo(tmp_path):
    """Se borran al arrancar: solo guardaban cookies, y SUNAT no reutiliza
    la sesión entre ejecuciones."""
    cfg = replace(Config(data_dir=tmp_path))
    viejo = cfg.profiles_dir / "20111111111"
    (viejo / "Default").mkdir(parents=True)
    (viejo / "Local State").write_text("{}", encoding="utf-8")
    # El del esquema nuevo no debe confundirse con uno viejo.
    cfg.perfil_de("20111111111", "tramites").mkdir(parents=True)

    encontrados = cfg.perfiles_del_esquema_viejo()
    assert encontrados == [viejo]


def test_no_confunde_un_perfil_nuevo_con_uno_viejo(tmp_path):
    cfg = replace(Config(data_dir=tmp_path))
    nuevo = cfg.perfil_de("20111111111", "tramites")
    (nuevo / "Default").mkdir(parents=True)
    assert cfg.perfiles_del_esquema_viejo() == []


def test_tambien_detecta_el_esquema_intermedio(tmp_path):
    """`profiles/<RUC>/<plataforma>/` fue un paso intermedio que dejaba un
    perfil de Chrome dentro de otro."""
    cfg = replace(Config(data_dir=tmp_path))
    intermedio = cfg.profiles_dir / "20111111111" / "tramites"
    (intermedio / "Default").mkdir(parents=True)

    assert cfg.perfiles_del_esquema_viejo() == [cfg.profiles_dir / "20111111111"]


def test_limpiar_borra_los_viejos_y_respeta_los_nuevos(tmp_path):
    from sunat.config import limpiar_perfiles_viejos

    cfg = replace(Config(data_dir=tmp_path))
    (cfg.profiles_dir / "20111111111" / "Default").mkdir(parents=True)
    nuevo = cfg.perfil_de("20222222222", "declaraciones")
    nuevo.mkdir(parents=True)

    assert limpiar_perfiles_viejos(cfg) == ["20111111111"]
    assert not (cfg.profiles_dir / "20111111111").exists()
    assert nuevo.exists(), "no debe tocar los perfiles del esquema actual"


def test_dos_rucs_no_comparten_perfil(tmp_path):
    cfg = replace(Config(data_dir=tmp_path))
    a = cfg.perfil_de("20111111111", "tramites")
    b = cfg.perfil_de("20222222222", "tramites")
    assert a != b
