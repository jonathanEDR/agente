"""Pruebas de los repositorios y del modelo zero-knowledge.

Lo central que se verifica aquí: el repositorio —sea archivo o API— solo
maneja texto cifrado, y el mismo vault se puede reabrir desde otra máquina
con la contraseña maestra y nada más.

El repositorio de API se prueba contra un doble del transporte HTTP, así
que no hace falta ni backend ni Mongo corriendo.
"""

from __future__ import annotations

import json

import pytest

from sunat.crypto import Caja, ParametrosKDF
from sunat.errors import ClaveMaestraInvalida, VaultCorrupto, VaultNoExiste
from sunat.repositorios import Empresa, RepositorioApi, RepositorioArchivo
from sunat.store import Vault


# --- criptografía -----------------------------------------------------------


def test_la_misma_password_y_salt_dan_la_misma_llave():
    """Es lo que hace posible descifrar desde otra computadora."""
    from sunat.crypto import derivar_llave

    params = ParametrosKDF.nuevos()
    assert derivar_llave("clave", params) == derivar_llave("clave", params)


def test_distinto_salt_da_distinta_llave():
    from sunat.crypto import derivar_llave

    assert derivar_llave("clave", ParametrosKDF.nuevos()) != derivar_llave(
        "clave", ParametrosKDF.nuevos()
    )


def test_salt_distinto_por_boveda():
    assert ParametrosKDF.nuevos().salt != ParametrosKDF.nuevos().salt


def test_parametros_ida_y_vuelta():
    original = ParametrosKDF.nuevos()
    copia = ParametrosKDF.desde_dict(original.a_dict())
    assert copia == original


def test_parametros_corruptos():
    with pytest.raises(VaultCorrupto):
        ParametrosKDF.desde_dict({"salt": "x"})


def test_caja_descifra_lo_que_cifra():
    caja, _params, _check = Caja.nueva("clave-maestra-de-prueba")
    assert caja.descifrar(caja.cifrar("claveSOL")) == "claveSOL"


def test_caja_rechaza_password_equivocada():
    _caja, params, check = Caja.nueva("correcta-y-bien-larga")
    with pytest.raises(ClaveMaestraInvalida):
        Caja.abrir("incorrecta-y-bien-larga", params, check)


def test_caja_reabierta_descifra_lo_de_antes():
    caja, params, check = Caja.nueva("clave-larga-de-verdad")
    token = caja.cifrar("secreto")
    assert (
        Caja.abrir("clave-larga-de-verdad", params, check).descifrar(token)
        == "secreto"
    )


# --- doble del transporte HTTP ----------------------------------------------


class ApiFalsa(RepositorioApi):
    """RepositorioApi con el transporte sustituido por un dict en memoria.

    Las rutas son las del contrato v1 del backend. El prefijo /api/v1 no
    aparece aquí porque lo pone `_pedir`, que es justo lo que este doble
    sustituye.
    """

    def __init__(self):
        super().__init__("http://falsa", "token-de-dispositivo")
        self.boveda: dict | None = None
        self.empresas: dict[str, dict] = {}
        self.llamadas: list[tuple[str, str]] = []

    def _pedir(self, metodo, ruta, cuerpo=None):
        self.llamadas.append((metodo, ruta))

        if ruta == "/vault":
            if metodo == "GET":
                return self.boveda
            self.boveda = cuerpo
            return cuerpo

        if ruta == "/companies" and metodo == "GET":
            return list(self.empresas.values())

        if ruta.startswith("/companies/"):
            ruc = ruta.rsplit("/", 1)[1]
            if metodo == "PUT":
                self.empresas[ruc] = cuerpo
                return cuerpo
            if metodo == "DELETE":
                self.empresas.pop(ruc, None)
                return None
        raise AssertionError(f"llamada inesperada: {metodo} {ruta}")


# --- los dos repositorios se comportan igual --------------------------------


@pytest.fixture(params=["archivo", "api"])
def repo(request, tmp_path):
    if request.param == "archivo":
        return RepositorioArchivo(tmp_path / "vault.json")
    return ApiFalsa()


def test_boveda_nueva_no_existe(repo):
    assert repo.existe() is False


def test_crear_y_reabrir(repo):
    vault = Vault.crear(repo, "maestra-de-prueba")
    vault.upsert("Constructora Matto", "20111111111", "USR1", "claveSOL")

    reabierto = Vault.abrir(repo, "maestra-de-prueba")
    empresas = reabierto.listar()
    assert len(empresas) == 1
    assert reabierto.clave_de(empresas[0]) == "claveSOL"


def test_password_incorrecta(repo):
    Vault.crear(repo, "correcta-y-bien-larga")
    with pytest.raises(ClaveMaestraInvalida):
        Vault.abrir(repo, "incorrecta-y-bien-larga")


def test_abrir_boveda_inexistente(repo):
    with pytest.raises(VaultNoExiste):
        Vault.abrir(repo, "x")


def test_upsert_reemplaza_por_ruc(repo):
    vault = Vault.crear(repo, "maestra-de-prueba")
    vault.upsert("Nombre viejo", "20111111111", "USR", "clave1")
    vault.upsert("Nombre nuevo", "20111111111", "USR2", "clave2")

    empresas = vault.listar()
    assert len(empresas) == 1
    assert empresas[0].nombre == "Nombre nuevo"
    assert vault.clave_de(empresas[0]) == "clave2"


def test_eliminar(repo):
    vault = Vault.crear(repo, "maestra-de-prueba")
    vault.upsert("A", "20111111111", "U", "c")
    vault.eliminar("20111111111")
    assert vault.listar() == []


def test_listado_ordenado_por_nombre(repo):
    vault = Vault.crear(repo, "maestra-de-prueba")
    vault.upsert("Zeta", "20111111111", "U", "c")
    vault.upsert("alfa", "20222222222", "U", "c")
    assert [e.nombre for e in vault.listar()] == ["alfa", "Zeta"]


# --- lo que el almacenamiento NO debe ver -----------------------------------


def test_el_archivo_no_guarda_la_clave_en_claro(tmp_path):
    ruta = tmp_path / "vault.json"
    Vault.crear(RepositorioArchivo(ruta), "maestra-de-prueba").upsert(
        "E", "20111111111", "U", "claveSOLsecreta"
    )
    assert "claveSOLsecreta" not in ruta.read_text(encoding="utf-8")


def test_la_api_nunca_recibe_la_clave_en_claro():
    """Lo que se manda por la red es un token, no la contraseña SOL."""
    api = ApiFalsa()
    Vault.crear(api, "maestra-de-prueba").upsert("E", "20111111111", "U", "claveSOLsecreta")

    enviado = json.dumps(api.empresas)
    assert "claveSOLsecreta" not in enviado
    assert api.empresas["20111111111"]["clave_cifrada"].startswith("gAAAA")


def test_la_api_nunca_recibe_la_password_maestra():
    api = ApiFalsa()
    Vault.crear(api, "contrasena-maestra").upsert("E", "20111111111", "U", "x")

    todo = json.dumps([api.boveda, api.empresas])
    assert "contrasena-maestra" not in todo


def test_otra_computadora_solo_necesita_la_password():
    """El caso de uso central: mismo backend, máquina sin datos locales."""
    api = ApiFalsa()
    Vault.crear(api, "maestra-de-prueba").upsert("Matto", "20111111111", "USR", "claveSOL")

    # Otra máquina: mismo repositorio remoto, ningún archivo local.
    desde_otra_pc = Vault.abrir(api, "maestra-de-prueba")
    assert desde_otra_pc.clave_de(desde_otra_pc.listar()[0]) == "claveSOL"


def test_archivo_con_json_invalido(tmp_path):
    ruta = tmp_path / "vault.json"
    ruta.write_text("{ esto no es json", encoding="utf-8")
    with pytest.raises(VaultCorrupto):
        Vault.abrir(RepositorioArchivo(ruta), "maestra-de-prueba")


def test_archivo_de_version_desconocida(tmp_path):
    ruta = tmp_path / "vault.json"
    ruta.write_text(json.dumps({"version": 999}), encoding="utf-8")
    with pytest.raises(VaultCorrupto):
        Vault.abrir(RepositorioArchivo(ruta), "maestra-de-prueba")


def test_vault_acepta_una_ruta_directamente(tmp_path):
    """Comodidad heredada: Vault.abrir(ruta, password) sigue funcionando."""
    ruta = tmp_path / "vault.json"
    Vault.crear(ruta, "maestra-de-prueba").upsert("E", "20111111111", "U", "clave")
    assert Vault.abrir(ruta, "maestra-de-prueba").listar()[0].ruc == "20111111111"


def test_una_boveda_no_abre_los_datos_de_otra():
    """Salts distintos: la contraseña de una bóveda no sirve en la otra."""
    api_a, api_b = ApiFalsa(), ApiFalsa()
    Vault.crear(api_a, "misma-password-larga").upsert("A", "20111111111", "U", "claveA")
    vault_b = Vault.crear(api_b, "misma-password-larga")

    prestada = Empresa.desde_dict(api_a.empresas["20111111111"])
    with pytest.raises(VaultCorrupto):
        vault_b.clave_de(prestada)


# --- contraseña maestra mínima ----------------------------------------------


def test_no_deja_crear_una_boveda_con_password_corta(repo):
    """Una bóveda es irrecuperable: un tecleo accidental de dos letras
    enterraría los datos para siempre. Pasó una vez en pruebas reales."""
    from sunat.errors import PasswordDebil

    with pytest.raises(PasswordDebil):
        Vault.crear(repo, "ab")


def test_acepta_una_frase_larga(repo):
    """Una frase de varias palabras vale aunque no tenga simbolos.

    Es lo contrario de lo que suelen pedir estos formularios, y es lo
    correcto: obligar a meter un simbolo en una frase de treinta caracteres
    solo consigue que la gente la acorte y la apunte en un papel.
    """
    Vault.crear(repo, "mi gato duerme sobre el teclado")
    assert repo.existe()


@pytest.mark.parametrize(
    "password,motivo",
    [
        ("Sun4t!", "demasiado corta"),
        ("contabilidad", "palabra sola de diccionario"),
        ("Sunat2024", "corta, y el ano al final no cuenta"),
        ("Contrasena2024", "sin tildes y sin el ano, es 'contrasena'"),
        ("xxxxxxxxxxxx", "un solo caracter repetido"),
        ("abcdefghijkl", "teclas seguidas"),
        ("micontrasena1", "menos de 16 y solo dos tipos de caracter"),
    ],
)
def test_rechaza_contrasenas_que_no_aguantan_un_ataque_sin_conexion(
    repo, password, motivo
):
    """El atacante no las prueba contra el agente sino sin conexion.

    Con el token de dispositivo se lleva la cabecera de la boveda y las
    claves cifradas, y desde ahi prueba a la velocidad de su hardware. Un
    diccionario de las mil mas usadas se agota en minutos por larga que sea
    cada entrada, asi que la longitud sola no alcanza.
    """
    from sunat.errors import PasswordDebil

    with pytest.raises(PasswordDebil):
        Vault.crear(repo, password)


def test_abrir_no_aplica_la_politica(tmp_path, monkeypatch):
    """La regla aplica al crear, no al abrir.

    Una boveda creada cuando el minimo eran 8 caracteres tiene que seguir
    abriendo: aplicarle la politica de hoy dejaria sus datos enterrados, que
    es exactamente el dano que la politica quiere evitar.
    """
    import sunat.crypto as cripto
    from sunat.repositorios import RepositorioArchivo

    ruta = tmp_path / "vieja.json"
    monkeypatch.setattr(cripto, "validar_password_nueva", lambda _p: None)
    Vault.crear(RepositorioArchivo(ruta), "corta")

    monkeypatch.undo()
    assert Vault.abrir(RepositorioArchivo(ruta), "corta").listar() == []


def test_una_boveda_nueva_no_nace_debil(repo):
    from sunat.crypto import SCRYPT_N

    vault = Vault.crear(repo, "mi gato duerme sobre el teclado")
    assert vault.kdf_debil is False
    assert vault._params.n == SCRYPT_N


def test_una_boveda_vieja_se_detecta_como_debil(tmp_path):
    """Las creadas con scrypt 2^15 siguen abriendo, pero se avisan.

    No se pueden migrar solas: cambiar los parametros obliga a volver a
    cifrar todas las claves, y hacerlo a medias dejaria la boveda ilegible.
    """
    from sunat.crypto import Caja, ParametrosKDF
    from sunat.repositorios import RepositorioArchivo

    repo = RepositorioArchivo(tmp_path / "vieja.json")
    params = ParametrosKDF(salt=ParametrosKDF.nuevos().salt, n=2**15, r=8, p=1)
    caja = Caja(__import__("cryptography.fernet", fromlist=["Fernet"]).Fernet(
        __import__("sunat.crypto", fromlist=["derivar_llave"]).derivar_llave(
            "mi gato duerme sobre el teclado", params
        )
    ))
    repo.crear(params, caja.cifrar("sunat-launcher-vault-v1"))

    assert Vault.abrir(repo, "mi gato duerme sobre el teclado").kdf_debil is True


# --- 401 no es lo mismo que 403 ---------------------------------------------


class _ErrorHttpFalso(Exception):
    """Lo minimo de urllib.error.HTTPError que usa `_pedir`."""

    def __init__(self, code, cuerpo):
        self.code = code
        self._cuerpo = json.dumps(cuerpo).encode("utf-8")

    def read(self):
        return self._cuerpo


def _api_que_responde(monkeypatch, code, cuerpo):
    import urllib.error
    import urllib.request

    from sunat.repositorios import RepositorioApi

    monkeypatch.setattr(urllib.error, "HTTPError", _ErrorHttpFalso, raising=False)

    def urlopen_falso(*_a, **_kw):
        raise _ErrorHttpFalso(code, cuerpo)

    monkeypatch.setattr(urllib.request, "urlopen", urlopen_falso)
    return RepositorioApi("https://api.ejemplo.com", "sla_" + "a" * 64)


def test_un_401_significa_token_revocado(monkeypatch):
    from sunat.repositorios import TokenRechazado

    api = _api_que_responde(monkeypatch, 401, {"error": "No autorizado."})

    with pytest.raises(TokenRechazado):
        api.existe()


def test_un_403_no_es_un_token_revocado(monkeypatch):
    """El limite del plan llega como 403, y el usuario tiene que leerlo.

    Cuando los dos codigos se trataban igual, quedarse sin cupo aparecia en
    pantalla como "el backend rechazo el token de esta computadora" y el panel
    llegaba a mostrar el equipo como revocado. Dos problemas distintos con la
    misma cara, y el consejo equivocado para uno de los dos.
    """
    from sunat.repositorios import ErrorApi, TokenRechazado

    limite = "Tu plan Free permite hasta 4 empresas y ya tienes 4."
    api = _api_que_responde(monkeypatch, 403, {"error": limite})

    with pytest.raises(ErrorApi) as capturado:
        api.existe()

    assert not isinstance(capturado.value, TokenRechazado)
    # El mensaje del backend llega intacto: es el que explica que hacer.
    assert str(capturado.value) == limite
