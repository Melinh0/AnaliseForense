import os
import warnings

from volatility3.framework import automagic, contexts
from volatility3.framework.plugins import construct_plugin
from volatility3.plugins.windows import (
    cmdline,
    dlllist,
    envars,
    filescan,
    handles,
    hollowprocesses,
    ldrmodules,
    malfind,
    netscan,
    privileges,
    pslist,
    psxview,
    svcscan,
    suspicious_threads,
)

warnings.filterwarnings("ignore", category=FutureWarning)

NAO_LEGIVEL = (
    "volatility3.framework.renderers.UnreadableValue",
    "volatility3.framework.renderers.NotApplicableValue",
    "volatility3.framework.renderers.UnparsableValue",
    "NotApplicableValue",
    "UnreadableValue",
    "UnparsableValue",
)


def fmt(valor):
    if valor is None:
        return "N/A"
    nome = type(valor).__module__ + "." + type(valor).__name__
    if any(f in nome for f in NAO_LEGIVEL):
        return "NAO-LEGIVEL"
    texto = str(valor)
    if "Value object at" in texto and "volatility3" in texto:
        return "NAO-LEGIVEL"
    return texto


def build_plugin(dump_path, plugin_class):
    ctx = contexts.Context()
    available = automagic.available(ctx)
    chosen = automagic.choose_automagic(available, plugin_class)
    ctx.config["automagic.LayerStacker.single_location"] = "file://" + os.path.abspath(dump_path)
    ctx.config["automagic.LayerStacker.stackers"] = automagic.stacker.choose_os_stackers(plugin_class)
    return construct_plugin(ctx, chosen, plugin_class, "plugins", None, None)


def coletar(dump_path, plugin_class):
    plugin = build_plugin(dump_path, plugin_class)
    treegrid = plugin.run()
    colunas = [col.name for col in treegrid.columns]
    linhas = []

    def visitor(node, acc):
        acc.append({nome: fmt(node.values[i]) for i, nome in enumerate(colunas)})
        return acc

    treegrid.populate(visitor, linhas)
    return linhas


def coluna(row, *candidatos, padrao="N/A"):
    for nome in candidatos:
        if nome in row:
            return row[nome]
    alvo = [c.lower() for c in candidatos]
    for nome, valor in row.items():
        if nome.lower() in alvo:
            return valor
    return padrao


def coletar_processos(dump):
    return coletar(dump, pslist.PsList)


def coletar_cmdlines(dump):
    return coletar(dump, cmdline.CmdLine)


def coletar_rede(dump):
    return coletar(dump, netscan.NetScan)


def coletar_injecoes(dump):
    return coletar(dump, malfind.Malfind)


def coletar_servicos(dump):
    return coletar(dump, svcscan.SvcScan)


def coletar_arquivos_memoria(dump):
    return coletar(dump, filescan.FileScan)


def coletar_psxview(dump):
    return coletar(dump, psxview.PsXView)


def coletar_dlllist(dump):
    return coletar(dump, dlllist.DllList)


def coletar_handles(dump):
    return coletar(dump, handles.Handles)


def coletar_privilegios(dump):
    return coletar(dump, privileges.Privs)


def coletar_dlls_ocultas(dump):
    return coletar(dump, ldrmodules.LdrModules)


def coletar_process_hollowing(dump):
    return coletar(dump, hollowprocesses.HollowProcesses)


def coletar_threads_suspeitas(dump):
    return coletar(dump, suspicious_threads.SuspiciousThreads)


def coletar_variaveis_ambiente(dump):
    return coletar(dump, envars.Envars)


def coletar_tudo(dump, progresso=print):
    tarefas = [
        ("processos", "pslist", coletar_processos),
        ("cmdlines", "cmdline", coletar_cmdlines),
        ("rede", "netscan", coletar_rede),
        ("injecoes", "malfind", coletar_injecoes),
        ("servicos", "svcscan", coletar_servicos),
        ("arquivos_memoria", "filescan", coletar_arquivos_memoria),
        ("psxview", "psxview", coletar_psxview),
        ("dlllist", "dlllist", coletar_dlllist),
        ("dlls_ocultas", "ldrmodules", coletar_dlls_ocultas),
        ("process_hollowing", "hollowprocesses", coletar_process_hollowing),
        ("threads_suspeitas", "suspicious_threads", coletar_threads_suspeitas),
        ("handles", "handles", coletar_handles),
        ("privilegios", "privs", coletar_privilegios),
        ("variaveis_ambiente", "envars", coletar_variaveis_ambiente),
    ]
    dados = {}
    erros = []
    for chave, nome, funcao in tarefas:
        progresso(f"Coletando {nome}...")
        try:
            dados[chave] = funcao(dump)
            progresso(f"  {nome}: {len(dados[chave])} registros")
        except Exception as exc:
            progresso(f"  erro em {nome}: {exc}")
            dados[chave] = []
            erros.append(f"{nome}: {exc}")
    dados["_erros"] = erros
    return dados
