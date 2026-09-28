import argparse
import pickle
import sys
import time
from pathlib import Path

import coletores_disco
import coletores_memoria
import deteccao
import integridade
import relatorio_pdf

BASE = Path(__file__).resolve().parent
CACHE_DIR = BASE / "data" / "cache"
SAIDA_DIR = BASE / "data" / "relatorios"


def parse_args():
    p = argparse.ArgumentParser(description="Relatório forense automatizado")
    p.add_argument("--memoria", default=str(BASE / "data" / "memory.raw"),
                   help="caminho do dump de memória")
    p.add_argument("--disco", default=str(BASE / "data" / "disk.dd"),
                   help="caminho da imagem de disco")
    p.add_argument("--offset", type=int, default=0, help="offset do sistema de arquivos")
    p.add_argument("--saida", default=str(SAIDA_DIR / "relatorio_forense.pdf"),
                   help="caminho do PDF de saída")
    p.add_argument("--sem-cache", action="store_true",
                   help="ignora o cache em data/cache e reexecuta tudo")
    return p.parse_args()


def carregar_ou_coletar(chave, funcao, sem_cache, progresso=print):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / f"{chave}.pkl"
    if cache.exists() and not sem_cache:
        progresso(f"Usando cache: {cache.name}")
        with open(cache, "rb") as fh:
            return pickle.load(fh)
    dados = funcao()
    if dados.get("_erros"):
        progresso(f"Coleta com erros em {chave}: cache NÃO gravado "
                  f"({len(dados['_erros'])} plugin(s) falharam)")
        return dados
    with open(cache, "wb") as fh:
        pickle.dump(dados, fh)
    return dados


def montar_veredicto(achados):
    if not achados:
        return ("Nenhum indício de ameaça foi detectado nas regras aplicadas. "
                "Isso não descarta comprometimento: significa que as evidências "
                "coletadas não atingiram os critérios das regras.")
    criticos = [a for a in achados if a.severidade == "CRÍTICO"]
    altos = [a for a in achados if a.severidade == "ALTO"]
    partes = []
    if criticos:
        partes.append(
            f"{len(criticos)} achado(s) CRÍTICO(S) "
            f"({', '.join(a.id for a in criticos)}) comprovam indício de comprometimento"
        )
    if altos:
        partes.append(
            f"{len(altos)} achado(s) de severidade ALTA "
            f"({', '.join(a.id for a in altos)}) reforcam a hipótese de atividade maliciosa"
        )
    texto = "; ".join(partes) + ". "
    texto += ("Conclusão: há indícios suficientes de ameaça/vulnerabilidade nas imagens "
              "analisadas, com cadeia de prova formada pela correlação entre processos, "
              "linhas de comando, regiões de memória, conexões de rede e conteúdo em disco.")
    return texto


def main():
    args = parse_args()
    inicio = time.time()

    print("Iniciando análise forense...")
    if not Path(args.memoria).exists():
        print(f"[AVISO] Dump de memória não encontrado: {args.memoria}")
    if not Path(args.disco).exists():
        print(f"[AVISO] Imagem de disco não encontrada: {args.disco}")

    midias = {"Memória (dump)": args.memoria, "Disco (imagem)": args.disco}
    print()
    print("Integridade das mídias - hash ANTES da análise (MD5/SHA256):")
    hash_inicio = integridade.calcular(midias)

    dados_memoria = {}
    if Path(args.memoria).exists():
        dados_memoria = carregar_ou_coletar(
            "memoria",
            lambda: coletores_memoria.coletar_tudo(args.memoria),
            args.sem_cache,
        )
    else:
        print("Pulando coleta de memória.")

    dados_disco = {}
    if Path(args.disco).exists():
        dados_disco = carregar_ou_coletar(
            "disco",
            lambda: coletores_disco.coletar_tudo(args.disco, offset=args.offset),
            args.sem_cache,
        )
    else:
        print("Pulando coleta de disco.")

    print("Executando motor de detecção...")
    achados = deteccao.analisar(dados_memoria, dados_disco)
    veredicto = montar_veredicto(achados)

    print()
    print("Integridade das mídias - hash DEPOIS da análise (MD5/SHA256):")
    hash_fim = integridade.calcular(midias)
    situacao = integridade.comparar(hash_inicio, hash_fim)
    midias_hash = {"inicio": hash_inicio, "fim": hash_fim, "situacao": situacao}
    for rotulo, estado in situacao.items():
        print(f"  {rotulo}: {estado}")
    print(f"  veredito: {integridade.resumo_veredicto(situacao)}")

    print()
    print("=" * 70)
    print("INDÍCIOS DETECTADOS")
    print("=" * 70)
    for a in achados:
        print(f"[{a.severidade:^8}] {a.id} - {a.titulo} ({len(a.evidencias)} provas)")
        for ev in a.evidencias[:3]:
            print(f"            - {ev}")
        if len(a.evidencias) > 3:
            print(f"            ... +{len(a.evidencias) - 3} provas")
    print("=" * 70)
    print(f"Veredicto: {veredicto}")
    print()

    saida = Path(args.saida)
    saida.parent.mkdir(parents=True, exist_ok=True)
    print("Gerando relatório PDF...")
    relatorio_pdf.build_pdf(
        dados_memoria, dados_disco, achados, veredicto,
        args.memoria, args.disco, args.offset, str(saida),
        integridade=midias_hash,
    )
    print(f"Relatório PDF gerado: {saida}")
    print(f"Tempo total: {time.time() - inicio:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
