"""Todos los selectores del portal, en un solo archivo.

Cuando SUNAT cambie el portal, lo primero que se rompe es esto. Tenerlo
aislado convierte "SUNAT cambió algo" en editar un archivo, en vez de una
cacería por todo el código.

Convención: marca cada selector como CONFIRMADO (visto en el HTML real) o
POR CONFIRMAR (suposición razonable que todavía no viste ocurrir).
"""

from __future__ import annotations

# --- Formulario de login (CONFIRMADO en vivo) -------------------------------
# Viven en api-seguridad.sunat.gob.pe/v1/clientessol/<client_id>/oauth2/
# loginMenuSol, a donde redirige sola la URL de entrada de cada
# plataforma (ver plataformas.py). Son los mismos en todas.
# Verificables en cualquier momento con: sunat doctor
RUC = "#txtRuc"
USUARIO = "#txtUsuario"
CLAVE = "#txtContrasena"
BOTON_INGRESAR = "#btnAceptar"

# Contenedor de error del propio formulario SOL: credenciales inválidas,
# RUC no habido, usuario bloqueado. Si aparece visible, el login falló.
MENSAJE_ERROR = "#divMensajeError .alert"

# Los que deben existir sí o sí para que el login automático funcione.
# `sunat doctor` los verifica contra el portal en vivo, sin autenticarse.
SELECTORES_LOGIN = {
    "campo RUC": RUC,
    "campo usuario": USUARIO,
    "campo clave": CLAVE,
    "botón ingresar": BOTON_INGRESAR,
}

# --- Menú SOL autenticado (CONFIRMADO en vivo) ------------------------------
# Marcador positivo de "estoy dentro". Es más fiable que deducirlo de la URL:
# la URL de entrada ya vive en e-menu.sunat.gob.pe antes de autenticarse.
MENU_USUARIO = "#aOpcionUsuario2"  # "Bienvenido, <razón social>"
MENU_BOTON_SALIR = "#btnSalir"
MARCADOR_MENU_AUTENTICADO = f"{MENU_USUARIO}, {MENU_BOTON_SALIR}"

# Entrada al Buzón Electrónico desde la cabecera del menú. Presente en
# las dos plataformas.
MENU_BUZON = "#aOpcionBuzon"

# --- Iframes del menú (CONFIRMADO en vivo) ----------------------------------
# El contenido de los módulos NO se renderiza en la página principal:
# `page.locator()` no lo ve. Hay que entrar al frame (ver navigation.py).
#
# Ojo con una trampa: `ifrVCE` existe desde el arranque pero se queda en
# about:blank. El módulo abierto vive en `iframeApplication`, que aparece
# recién DESPUÉS del clic.
FRAME_APP = "iframeApplication"
FRAME_MENSAJE = "contenedorMensaje"  # detalle de un mensaje abierto
FRAME_VCE = "ifrVCE"  # presente siempre, normalmente vacío

# Frames de infraestructura: control de expiración de sesión, no contenido.
FRAMES_INFRAESTRUCTURA = ("iframeTime", "iframeAnterior", FRAME_VCE)

# --- Aviso de sesión ya abierta (POR CONFIRMAR) ----------------------------
# SUNAT muestra a veces un aviso del tipo "Ya tiene una sesión abierta,
# ¿desea continuar?" cuando quedó una sesión previa sin cerrar. Todavía no
# tenemos el id real del diálogo, así que lo detectamos por texto visible y
# confirmamos con un botón cuyo texto coincida.
#
# Mientras esté POR CONFIRMAR, si el texto no matchea el login termina en
# REQUIERE_INTERVENCION y se vuelca un diagnóstico — que es exactamente el
# insumo que necesitas para reemplazar esto por un selector real.
TEXTO_SESION_ACTIVA = (
    r"(sesi[oó]n\s+(activa|abierta|en\s+curso))|(ya\s+tiene\s+una\s+sesi[oó]n)"
)
BOTON_CONTINUAR_SESION = (
    "button:has-text('Continuar'), "
    "button:has-text('Aceptar'), "
    "input[type='button'][value*='ontinuar'], "
    "a:has-text('Continuar')"
)

# --- Página de verificación anti-bot (CONFIRMADO en vivo) -------------------
# Tras varios logins seguidos desde la misma IP, SUNAT devuelve una página
# mínima (~168 bytes) en vez del menú:
#
#   <title>Bienvenido a SUNAT</title>
#   <h1><check>Bienvenidos a SUNAT</check></h1>
#
# El tag <check> no es HTML estándar; viene del F5 que SUNAT tiene delante
# (se ve `f5_cspm` en el iframe de reloj). No es un rechazo de credenciales:
# es limitación de ritmo. Se trata como transitorio y se espacia el reintento.
MARCADOR_VERIFICACION = "check"
TITULO_VERIFICACION = "Bienvenido a SUNAT"

# --- Señales de captcha (CONFIRMADO que el campo existe) --------------------
# El formulario de SOL trae `#txtCaptcha` en el HTML de forma permanente,
# pero oculto: SUNAT lo muestra solo cuando decide exigirlo. Por eso la
# detección mira VISIBILIDAD y no presencia — buscar el id a secas daría un
# falso positivo en todos los logins normales.
#
# No intentamos resolverlo: solo detectarlo, para decir "esto necesita que
# mires la pantalla" en vez de fallar con un timeout mudo.
INDICIOS_CAPTCHA = (
    "#txtCaptcha, "
    "iframe[src*='recaptcha'], "
    "iframe[src*='hcaptcha'], "
    "div.g-recaptcha, "
    "#captcha"
)
