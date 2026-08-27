"""Pruebas de los diálogos nativos.

No verifican que aparezca un diálogo de verdad —eso es UI de Windows, no
algo que tenga sentido automatizar— sino que llamarlas nunca reviente,
incluyendo bajo pytest en Linux/CI donde `ctypes.windll` ni siquiera
existe.
"""

from __future__ import annotations

from sunat import avisos


def test_avisar_no_revienta():
    avisos.avisar("mensaje de prueba")


def test_avisar_error_no_revienta():
    avisos.avisar_error("mensaje de prueba")
