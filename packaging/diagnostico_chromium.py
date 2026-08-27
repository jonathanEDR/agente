"""Prueba aislada: solo abre Chromium y navega a una pagina en blanco.

Sirve para verificar que el navegador arranca correctamente DENTRO del
.exe empaquetado, sin tocar SUNAT ni depender de credenciales. Fija
PLAYWRIGHT_BROWSERS_PATH igual que arranque.py, para probar exactamente
el mismo mecanismo antes de reconstruir el agente completo.
"""
import os

os.environ.setdefault(
    "PLAYWRIGHT_BROWSERS_PATH",
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright"),
)

from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    print("driver resuelto, lanzando chromium headless...")
    b = p.chromium.launch(headless=True)
    page = b.new_page()
    page.goto("about:blank")
    print("CHROMIUM_OK titulo=", repr(page.title()))
    b.close()
print("listo")
