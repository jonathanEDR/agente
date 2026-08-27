"""Pruebas de la lógica de descargas, sin abrir un navegador real.

`_elegir_ruta` es la parte que se puede probar sola: dónde guardar un
archivo dado su nombre sugerido y qué ya está reservado. Que Playwright de
verdad guarde ahí el contenido se verificó a mano contra un servidor local
—ver el hallazgo original: sin esto, Playwright pone un GUID por nombre en
una carpeta temporal que borra al cerrar el contexto.
"""

from __future__ import annotations

from sunat.browser import _elegir_ruta


def test_usa_el_nombre_sugerido_si_esta_libre(tmp_path):
    ruta = _elegir_ruta(tmp_path, "constancia.pdf", set())
    assert ruta == tmp_path / "constancia.pdf"


def test_evita_pisar_un_archivo_que_ya_existe_en_disco(tmp_path):
    (tmp_path / "constancia.pdf").write_bytes(b"ya estaba")

    ruta = _elegir_ruta(tmp_path, "constancia.pdf", set())

    assert ruta == tmp_path / "constancia (1).pdf"


def test_evita_pisar_un_nombre_solo_reservado_en_memoria(tmp_path):
    # El caso que importa: dos descargas de la misma sesion con el mismo
    # nombre sugerido, donde la primera todavia no llego a escribirse en
    # disco cuando se elige el nombre de la segunda.
    reservados = {tmp_path / "constancia.pdf"}

    ruta = _elegir_ruta(tmp_path, "constancia.pdf", reservados)

    assert ruta == tmp_path / "constancia (1).pdf"
    assert ruta in reservados


def test_tres_colisiones_seguidas(tmp_path):
    reservados: set = set()
    rutas = [_elegir_ruta(tmp_path, "aviso.txt", reservados) for _ in range(3)]

    assert rutas == [
        tmp_path / "aviso.txt",
        tmp_path / "aviso (1).txt",
        tmp_path / "aviso (2).txt",
    ]
    assert len(set(rutas)) == 3  # ninguna ruta se repite


def test_conserva_nombres_sin_extension(tmp_path):
    (tmp_path / "LEEME").write_bytes(b"x")

    ruta = _elegir_ruta(tmp_path, "LEEME", set())

    assert ruta == tmp_path / "LEEME (1)"
