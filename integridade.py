import hashlib
import os
import time
from datetime import datetime

CHUNK = 8 * 1024 * 1024

NAO_VERIFICAVEL = "NÃO-VERIFICÁVEL"
INALTERADA = "INALTERADA"
ALTERADA = "ALTERADA"
AUSENTE = "AUSENTE"


def _hash_arquivo(caminho, progresso=None):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    total = 0
    ultimo = time.time()
    with open(caminho, "rb") as fh:
        while True:
            bloco = fh.read(CHUNK)
            if not bloco:
                break
            md5.update(bloco)
            sha256.update(bloco)
            total += len(bloco)
            if progresso and time.time() - ultimo > 5:
                progresso(f"    {total / (1024 ** 3):.1f} GB lidos...")
                ultimo = time.time()
    return total, md5.hexdigest(), sha256.hexdigest()


def calcular(caminhos, progresso=print):
    resultado = {}
    for rotulo, caminho in (caminhos or {}).items():
        entrada = {
            "caminho": caminho or "-",
            "status": AUSENTE,
            "tamanho": "-",
            "md5": "-",
            "sha256": "-",
            "quando": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        }
        if not caminho or not os.path.exists(caminho):
            resultado[rotulo] = entrada
            continue
        inicio = time.time()
        try:
            tamanho, md5, sha256 = _hash_arquivo(caminho, progresso)
        except OSError as exc:
            entrada["status"] = f"{NAO_VERIFICAVEL} ({exc})"
            resultado[rotulo] = entrada
            continue
        entrada.update({
            "status": "OK",
            "tamanho": tamanho,
            "md5": md5,
            "sha256": sha256,
            "quando": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        })
        resultado[rotulo] = entrada
        if progresso:
            progresso(f"  {rotulo}: MD5={md5} ({time.time() - inicio:.1f}s)")
    return resultado


def comparar(inicio, fim):
    situacao = {}
    for rotulo in sorted(set(inicio or {}) | set(fim or {})):
        a = (inicio or {}).get(rotulo, {})
        b = (fim or {}).get(rotulo, {})
        if a.get("status") != "OK" or b.get("status") != "OK":
            situacao[rotulo] = NAO_VERIFICAVEL
        elif a.get("md5") == b.get("md5") and a.get("sha256") == b.get("sha256"):
            situacao[rotulo] = INALTERADA
        else:
            situacao[rotulo] = ALTERADA
    return situacao


def resumo_veredicto(situacao):
    valores = list((situacao or {}).values())
    if not valores:
        return "não verificada"
    if all(s == INALTERADA for s in valores):
        return f"INALTERADA ({len(valores)} mídia(s) com MD5/SHA256 idênticos antes e depois da análise)"
    if any(s == ALTERADA for s in valores):
        return "ALTERADA - investigar antes de usar o laudo"
    return "parcialmente verificada"
