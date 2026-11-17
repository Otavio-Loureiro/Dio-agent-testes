import base64
import hashlib
import hmac
import secrets
import sqlite3
import time

# Configuracao de seguranca
_ITERACOES = 262144
_TAMANHO_SALT = 16
_MAX_TENTATIVAS = 5
_WINDOW_SEC = 900

_tentativas = {}

def _gerar_salt():
    return secrets.token_bytes(_TAMANHO_SALT)

def _hashear_bytes(senha, salt):
    return hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, _ITERACOES)

def _hashear_senha(senha, salt):
    return base64.b64encode(_hashear_bytes(senha, salt)).decode('ascii')

def _verificar_senha(senha, salt_b64, hash_b64):
    salt = base64.b64decode(salt_b64)
    esperado = base64.b64decode(hash_b64)
    calculado = _hashear_bytes(senha, salt)
    return hmac.compare_digest(calculado, esperado)

def _conectar():
    conexao = sqlite3.connect('banco_de_dados.db')
    conexao.row_factory = sqlite3.Row
    return conexao

def _lockout_ativo(usuario):
    chave = usuario.lower()
    now = time.time()
    if chave in _tentativas:
        qtde, expira = _tentativas[chave]
        if qtde >= _MAX_TENTATIVAS and now < expira:
            return True
        if expira and now >= expira:
            del _tentativas[chave]
    return False

def _registrar_tentativa(usuario, sucesso):
    chave = usuario.lower()
    if sucesso:
        _tentativas.pop(chave, None)
        return
    now = time.time()
    qtde, expira = _tentativas.get(chave, (0, 0))
    if expira and now < expira:
        return  # ainda dentro do bloqueio, nao atualiza a contagem
    qtde += 1
    if qtde >= _MAX_TENTATIVAS:
        _tentativas[chave] = (qtde, now + _WINDOW_SEC)
    else:
        _tentativas[chave] = (qtde, 0)

def cadastrar_usuario(conn, usuario, senha):
    salt = _gerar_salt()
    salt_b64 = base64.b64encode(salt).decode('ascii')
    hash_b64 = _hashear_senha(senha, salt)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO usuarios (username, senha_salt, senha_hash) VALUES (?, ?, ?)", (usuario, salt_b64, hash_b64))
    conn.commit()
    return "Usuario criado."

def fazer_login(usuario, senha):
    if _lockout_ativo(usuario):
        return "Acesso negado. Tente mais tarde."
    conexao = _conectar()
    try:
        cursor = conexao.cursor()
        cursor.execute("SELECT senha_salt, senha_hash FROM usuarios WHERE username = ?", (usuario,))
        linha = cursor.fetchone()
    finally:
        conexao.close()
    if linha is None:
        _registrar_tentativa(usuario, sucesso=False)
        return "Acesso Negado"
    if not _verificar_senha(senha, linha["senha_salt"], linha["senha_hash"]):
        _registrar_tentativa(usuario, sucesso=False)
        return "Acesso Negado"
    _registrar_tentativa(usuario, sucesso=True)
    return "Acesso concedido."
