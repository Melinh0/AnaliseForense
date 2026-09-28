import html
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

import metodologia
from integridade import resumo_veredicto

CORES_SEVERIDADE = {
    "CRÍTICO": colors.HexColor("#b71c1c"),
    "ALTO": colors.HexColor("#e65100"),
    "MÉDIO": colors.HexColor("#f9a825"),
    "BAIXO": colors.HexColor("#2e7d32"),
}

ESTILOS = getSampleStyleSheet()


def esc(texto):
    return html.escape(str(texto))


def estilo(nome, **kwargs):
    base = kwargs.pop("parent", ESTILOS["Normal"])
    return ParagraphStyle(nome, parent=base, **kwargs)


S_TITULO = estilo("Título", parent=ESTILOS["Heading1"], fontSize=18, spaceAfter=12,
                  textColor=colors.HexColor("#1a237e"))
S_SUB = estilo("Sub", parent=ESTILOS["Heading2"], fontSize=14, spaceAfter=8,
               textColor=colors.HexColor("#283593"))
S_SEC = estilo("Sec", parent=ESTILOS["Heading2"], fontSize=13, spaceBefore=10,
               spaceAfter=4, textColor=colors.HexColor("#283593"))
S_ROTULO = estilo("Rot", fontSize=9, textColor=colors.HexColor("#1a237e"))
S_DESC = estilo("Desc", fontSize=9)
S_CODE = estilo("Cod", fontSize=8, textColor=colors.HexColor("#4a148c"))
S_PROVA = estilo("Prova", fontSize=8, fontName="Courier",
                 backColor=colors.HexColor("#f5f5f5"), spaceAfter=3)
S_SEV_CRITICO = estilo("SevC", fontSize=10, textColor=colors.HexColor("#b71c1c"),
                       fontName="Helvetica-Bold")
S_SEV_ALTO = estilo("SevA", fontSize=10, textColor=colors.HexColor("#e65100"),
                    fontName="Helvetica-Bold")
S_SEV_MEDIO = estilo("SevM", fontSize=10, textColor=colors.HexColor("#f57f17"),
                     fontName="Helvetica-Bold")
S_SEV_BAIXO = estilo("SevB", fontSize=10, textColor=colors.HexColor("#2e7d32"),
                     fontName="Helvetica-Bold")
S_ESTILOS_SEV = {"CRÍTICO": S_SEV_CRITICO, "ALTO": S_SEV_ALTO,
                 "MÉDIO": S_SEV_MEDIO, "BAIXO": S_SEV_BAIXO}

LARGURA_UTIL = 595 - 36 * 2
S_CELL = estilo("Cell", fontSize=7, leading=8, alignment=0)
S_CELL_C = estilo("CellC", fontSize=7, leading=8, alignment=1)
S_CELL_H = estilo("CellH", fontSize=7, leading=8, alignment=1,
                  textColor=colors.white, fontName="Helvetica-Bold")


def tabela(dados, font_size=7):
    if not dados:
        return Spacer(1, 0)
    n_cols = len(dados[0])
    pesos = []
    for i in range(n_cols):
        maior = max((len(str(l[i])) if i < len(l) else 0) for l in dados)
        pesos.append(min(max(maior, 8), 70))
    soma = sum(pesos)
    larguras = [max(40.0, LARGURA_UTIL * p / soma) for p in pesos]
    ajuste = LARGURA_UTIL / sum(larguras)
    larguras = [w * ajuste for w in larguras]

    celulas = []
    for ri, linha in enumerate(dados):
        celulas.append([
            Paragraph(esc(linha[ci]) if ci < len(linha) and linha[ci] is not None else "",
                      S_CELL_H if ri == 0
                      else (S_CELL_C if font_size and len(str(linha[ci] if ci < len(linha) else "")) <= 18
                            else S_CELL))
            for ci in range(n_cols)
        ])
    t = Table(celulas, colWidths=larguras, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7ff")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def secao(elementos, titulo, tool, descricao, cli, api, cabecalho, linhas, limite=50):
    elementos.append(Paragraph(esc(titulo), S_SEC))
    elementos.append(Paragraph(f"<b>Ferramenta utilizada:</b> {esc(tool)}", S_ROTULO))
    elementos.append(Paragraph(f"<b>Descrição:</b> {esc(descricao)}", S_DESC))
    elementos.append(Paragraph(f"<b>Comando CLI equivalente:</b> <font face='Courier' size='8'>{esc(cli)}</font>", S_CODE))
    elementos.append(Paragraph(f"<b>Chamada API Python executada:</b> <font face='Courier' size='8'>{esc(api)}</font>", S_CODE))
    elementos.append(Spacer(1, 6))
    if linhas:
        elementos.append(tabela([cabecalho] + linhas[:limite]))
        elementos.append(Paragraph(f"Total de registros: {len(linhas)}", ESTILOS["Normal"]))
    else:
        elementos.append(Paragraph("Nenhum registro encontrado.", ESTILOS["Normal"]))
    elementos.append(Spacer(1, 14))


def _tabela_integridade(dados):
    linhas = [["Mídia", "Propriedade", "Valor"]]
    inicio = (dados or {}).get("inicio", {})
    fim = (dados or {}).get("fim", {})
    situacao = (dados or {}).get("situacao", {})
    for rotulo in list(inicio) + [r for r in fim if r not in inicio]:
        a = inicio.get(rotulo, {})
        b = fim.get(rotulo, {})
        linhas += [
            [rotulo, "Caminho",
             os.path.basename(str(a.get("caminho", b.get("caminho", "-"))))],
            ["", "Tamanho (bytes)", str(a.get("tamanho", "-"))],
            ["", "MD5 (antes)", str(a.get("md5", "-"))],
            ["", "MD5 (depois)", str(b.get("md5", "-"))],
            ["", "SHA256 (antes)", str(a.get("sha256", "-"))],
            ["", "SHA256 (depois)", str(b.get("sha256", "-"))],
            ["", "Leitura", f"antes {a.get('quando', '-')} / depois {b.get('quando', '-')}"],
            ["", "Situação", situacao.get(rotulo, "NÃO-VERIFICÁVEL")],
        ]
    return tabela(linhas)


def capitulo_metodologia(elementos, integridade=None):
    elementos.append(Paragraph(
        "CAPÍTULO 0 - METODOLOGIA E FUNDAMENTAÇÃO DAS EVIDÊNCIAS", S_TITULO))
    elementos.append(Paragraph(
        "Este capítulo responde duas perguntas do leitor: (1) como uma "
        "evidência do capítulo seguinte foi formada, do dump até a linha "
        "impressa no relatório, e (2) como o Volatility 3 e o The Sleuth Kit "
        "chegam ao dado que sustenta cada achado. Também documenta as "
        "ferramentas, a integridade das mídias analisadas, os critérios de "
        "severidade e as limitações do método.", S_DESC))
    elementos.append(Spacer(1, 10))

    elementos.append(Paragraph("0.1 Ferramentas utilizadas", S_SUB))
    elementos.append(Paragraph(
        "Todas as ferramentas operam em modo somente leitura sobre as "
        "mídias: nenhum arquivo de origem é montado em escrita ou executado.",
        S_DESC))
    elementos.append(Spacer(1, 4))
    elementos.append(tabela(metodologia.ferramentas()))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph("0.2 Integridade das mídias (hash antes e depois)", S_SUB))
    elementos.append(Paragraph(
        "Para garantir que a memória e a imagem de disco não foram "
        "adulteradas durante a análise, o MD5 e o SHA256 de cada mídia são "
        "calculados em uma única leitura antes da coleta e novamente depois "
        "da detecção. Hashes idênticos comprovam que a mídia analisada é a "
        "mesma em todos os momentos da perícia.", S_DESC))
    elementos.append(Spacer(1, 4))
    elementos.append(_tabela_integridade(integridade))
    elementos.append(Paragraph(
        "<b>Veredito de integridade:</b> "
        f"{esc(resumo_veredicto((integridade or {}).get('situacao')))}",
        S_DESC))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph("0.3 Como uma evidência é formada", S_SUB))
    elementos.append(Paragraph(
        "Cada achado AM-01..AM-10 nasce de um predicado executado sobre as "
        "fontes coletadas; quando o predicado é verdadeiro, ele emite uma "
        "linha por ocorrência concreta (PID, caminho, IP ou hash) - e essas "
        "linhas são as 'evidências' impressas no capítulo 1.", S_DESC))
    elementos.append(Spacer(1, 4))
    elementos.append(tabela(metodologia.PIPELINE))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph("0.4 Critérios de severidade", S_SUB))
    elementos.append(tabela(metodologia.SEVERIDADES))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph(
        "0.5 Como o Volatility 3 detecta (análise de memória)", S_SUB))
    elementos.append(Paragraph(
        "O Volatility não confia nas APIs do sistema suspeito: ele reconstrói "
        "as estruturas do kernel (EPROCESS, PEB, VAD, sockets, tokens) "
        "direto dos bytes do dump, por assinatura e por encadeamento de "
        "ponteiros. Por isso continua funcionando com processos ocultos, "
        "DLLs desvinculadas e injeções de código.", S_DESC))
    elementos.append(Spacer(1, 4))
    elementos.append(tabela(metodologia.VOLATILITY))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph(
        "0.6 Como o The Sleuth Kit detecta (análise de disco)", S_SUB))
    elementos.append(Paragraph(
        "O TSK (via pytsk3) abre a imagem como um arquivo comum e lê os "
        "metadados do sistema de arquivos diretamente - partições, MFT, "
        "entradas de diretório, bits de alocação e timestamps - sem montar "
        "o volume e sem arriscar alterar a mídia.", S_DESC))
    elementos.append(Spacer(1, 4))
    elementos.append(tabela(metodologia.TSK))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph("0.7 Cadeia de prova (correlação entre fontes)", S_SUB))
    elementos.append(Paragraph(
        "Um achado só entra no laudo com as fontes que o sustentam: os "
        "mesmos fatos aparecem em plugins diferentes (memória) e em "
        "metadados do disco, o que reduz falsos positivos.", S_DESC))
    elementos.append(Spacer(1, 4))
    elementos.append(tabela(metodologia.cadeia_prova()))
    elementos.append(Spacer(1, 8))

    elementos.append(Paragraph("0.8 Limitações do método", S_SUB))
    for item in metodologia.LIMITACOES:
        elementos.append(Paragraph(f"- {esc(item)}", S_DESC))
        elementos.append(Spacer(1, 2))

    elementos.append(PageBreak())


def capitulo_evidencias(elementos, achados, resumo, veredicto):
    elementos.append(Paragraph("CAPÍTULO 1 - EVIDÊNCIAS E INDÍCIOS DE AMEAÇAS", S_TITULO))
    elementos.append(Paragraph(
        "Análise automatizada de indícios de ameaça e vulnerabilidade, com correlação "
        "entre memória (Volatility 3) e disco (The Sleuth Kit). Cada achado abaixo traz "
        "a prova concreta, as fontes que se cruzam e a conclusão pericial.",
        S_DESC))
    elementos.append(Spacer(1, 10))

    elementos.append(Paragraph("1.1 Resumo executivo", S_SUB))
    total = sum(resumo.values())
    elementos.append(Paragraph(f"<b>Achados identificados:</b> {total}", ESTILOS["Normal"]))
    for sev in ("CRÍTICO", "ALTO", "MÉDIO", "BAIXO"):
        if resumo.get(sev):
            elementos.append(Paragraph(
                f"<font color='{CORES_SEVERIDADE[sev].hexval()}'><b>{sev}: {resumo[sev]}</b></font>",
                ESTILOS["Normal"]))
    elementos.append(Spacer(1, 6))
    elementos.append(Paragraph(f"<b>Veredicto:</b> {esc(veredicto)}", S_DESC))
    elementos.append(Spacer(1, 12))

    elementos.append(Paragraph("1.2 Tabela de achados", S_SUB))
    if achados:
        cabecalho = ["ID", "Severidade", "Achado", "Categoria", "Provas"]
        linhas = [[a.id, a.severidade, esc(a.titulo), esc(a.categoria),
                   str(len(a.evidencias))] for a in achados]
        elementos.append(tabela([cabecalho] + linhas, font_size=8))
    else:
        elementos.append(Paragraph("Nenhum indício detectado.", ESTILOS["Normal"]))
    elementos.append(Spacer(1, 14))

    elementos.append(Paragraph("1.3 Detalhamento das provas", S_SUB))
    for a in achados:
        elementos.append(Paragraph(f"{a.id} - {esc(a.titulo)}", S_SEC))
        elementos.append(Paragraph(a.severidade, S_ESTILOS_SEV.get(a.severidade, S_DESC)))
        elementos.append(Spacer(1, 2))
        elementos.append(Paragraph(
            f"<b>Comando que reproduz a prova:</b> <font face='Courier' size='8'>{esc(a.ferramenta)}</font>",
            S_CODE))
        if a.correlacao:
            elementos.append(Paragraph(
                "<b>Fontes correlacionadas:</b> " + esc(", ".join(a.correlacao)), S_DESC))
        elementos.append(Paragraph(f"<b>Conclusão:</b> {esc(a.conclusao)}", S_DESC))
        elementos.append(Spacer(1, 4))
        elementos.append(Paragraph(f"<b>Evidências ({len(a.evidencias)}):</b>", S_ROTULO))
        for ev in a.evidencias[:40]:
            elementos.append(Paragraph(esc(ev), S_PROVA))
        if len(a.evidencias) > 40:
            elementos.append(Paragraph(
                f"... {len(a.evidencias) - 40} evidências adicionais não listadas.",
                ESTILOS["Normal"]))
        elementos.append(Spacer(1, 10))

    elementos.append(PageBreak())


def build_pdf(memoria, disco, achados, veredicto, caminho_memoria, caminho_disco,
              offset_disco, output_path, integridade=None):
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=36, leftMargin=36,
                            topMargin=54, bottomMargin=36)
    elementos = []

    elementos.append(Paragraph("Relatório Forense Automatizado", S_TITULO))
    elementos.append(Paragraph(
        "Análise de Memória (Volatility 3) e Análise de Disco (The Sleuth Kit / pytsk3) "
        "com detecção de indícios de ameaça", S_SUB))
    elementos.append(Spacer(1, 10))
    elementos.append(Paragraph(f"Data de geração: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
                               ESTILOS["Normal"]))
    elementos.append(Paragraph(f"Arquivo de memória analisado: {esc(os.path.basename(caminho_memoria))}",
                               ESTILOS["Normal"]))
    elementos.append(Paragraph(f"Imagem de disco analisada: {esc(os.path.basename(caminho_disco))} (offset {offset_disco})",
                               ESTILOS["Normal"]))
    elementos.append(Paragraph(
        "<b>Integridade das mídias:</b> "
        f"{esc(resumo_veredicto((integridade or {}).get('situacao')))}",
        ESTILOS["Normal"]))
    elementos.append(Spacer(1, 16))
    elementos.append(PageBreak())

    capitulo_metodologia(elementos, integridade)

    resumo = {}
    for a in achados:
        resumo[a.severidade] = resumo.get(a.severidade, 0) + 1
    capitulo_evidencias(elementos, achados, resumo, veredicto)

    elementos.append(Paragraph("PARTE I - ANÁLISE DE MEMÓRIA (VOLATILITY 3)", S_SUB))
    elementos.append(Spacer(1, 6))

    secao(elementos, "1. Processos em Execução",
          "Volatility 3 - plugin pslist",
          "Lista todos os processos ativos no momento da captura da memória.",
          "vol -f <memoria> windows.pslist",
          "coletar_processos(dump)",
          ["PID", "PPID", "ImageFileName", "Threads", "Handles", "CreateTime"],
          [[r.get("PID"), r.get("PPID"), r.get("ImageFileName"), r.get("Threads"),
            r.get("Handles"), r.get("CreateTime")] for r in memoria.get("processos", [])])

    secao(elementos, "2. Linhas de Comando dos Processos",
          "Volatility 3 - plugin cmdline",
          "Linha de comando completa de cada processo (sem truncamento): base das provas AM-01 e AM-06.",
          "vol -f <memoria> windows.cmdline",
          "coletar_cmdlines(dump)",
          ["PID", "Process", "Args"],
          [[r.get("PID"), r.get("Process"), r.get("Args")] for r in memoria.get("cmdlines", [])],
          limite=80)

    secao(elementos, "3. Conexões de Rede",
          "Volatility 3 - plugin netscan",
          "Conexões TCP/UDP ativas e passivas com endereços, estado e processo responsável (prova AM-04 e AM-07).",
          "vol -f <memoria> windows.netscan",
          "coletar_rede(dump)",
          ["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner"],
          [[r.get("Proto"), r.get("LocalAddr"), r.get("LocalPort"), r.get("ForeignAddr"),
            r.get("ForeignPort"), r.get("State"), r.get("PID"), r.get("Owner")]
           for r in memoria.get("rede", [])],
          limite=80)

    secao(elementos, "4. Injeções de Código Suspeitas",
          "Volatility 3 - plugin malfind",
          "Regiões de memória executáveis sem correspondência em arquivo (prova AM-03).",
          "vol -f <memoria> windows.malfind",
          "coletar_injecoes(dump)",
          ["PID", "Process", "Start VPN", "End VPN", "Protection", "FileOutput"],
          [[r.get("PID"), r.get("Process"), r.get("Start VPN"), r.get("End VPN"),
            r.get("Protection"), r.get("FileOutput")] for r in memoria.get("injecoes", [])])

    secao(elementos, "5. Processos Ocultos (pslist x psscan/thrdscan)",
          "Volatility 3 - plugin psxview",
          "Comparativo entre a lista ativa de processos e a varredura de pool/threads. "
          "Divergências indicam ocultação ou processo finalizado remanescente (prova AM-02).",
          "vol -f <memoria> windows.psxview",
          "coletar_psxview(dump)",
          ["PID", "Name", "pslist", "psscan", "thrdscan", "csrss"],
          [[r.get("PID"), r.get("Name"), r.get("pslist"), r.get("psscan"),
            r.get("thrdscan"), r.get("csrss")] for r in memoria.get("psxview", [])],
          limite=80)

    secao(elementos, "6. Bibliotecas Carregadas (dlllist)",
          "Volatility 3 - plugin dlllist",
          "DLLs carregadas por processo; caminhos fora do padrão ajudam a confirmar injeção.",
          "vol -f <memoria> windows.dlllist",
          "coletar_dlllist(dump)",
          ["PID", "Process", "Base", "Path"],
          [[r.get("PID"), r.get("Process"), r.get("Base"), str(r.get("Path", ""))[:110]]
           for r in memoria.get("dlllist", [])],
          limite=60)

    secao(elementos, "7. DLLs Ocultas / Desvinculadas (ldrmodules)",
          "Volatility 3 - plugin ldrmodules",
          "Compara as três listas de DLLs do processo (InLoad, InInit, InMem) com os "
          "arquivos mapeados. DLL presente no disco mas ausente das listas indica "
          "unlinked DLL (DLL injection oculta).",
          "vol -f <memoria> windows.ldrmodules",
          "coletar_dlls_ocultas(dump)",
          ["PID", "Process", "Base", "InLoad", "InInit", "InMem", "MappedPath"],
          [[r.get("Pid"), r.get("Process"), r.get("Base"), r.get("InLoad"),
            r.get("InInit"), r.get("InMem"), str(r.get("MappedPath", ""))[:90]]
           for r in memoria.get("dlls_ocultas", [])],
          limite=60)

    secao(elementos, "8. Process Hollowing (hollowprocesses)",
          "Volatility 3 - plugin hollowprocesses",
          "Detecta processos com imagem original substituída por memória executável "
          "sem arquivo correspondente (process hollowing / RunPE).",
          "vol -f <memoria> windows.hollowprocesses",
          "coletar_process_hollowing(dump)",
          ["PID", "Process", "Notes"],
          [[r.get("PID"), r.get("Process"), str(r.get("Notes", ""))[:120]]
           for r in memoria.get("process_hollowing", [])],
          limite=60)

    secao(elementos, "9. Threads Suspeitas (suspicious_threads)",
          "Volatility 3 - plugin suspicious_threads",
          "Threads em execução cujo endereço de início não corresponde a nenhum "
          "módulo carregado (código injetado em região privada).",
          "vol -f <memoria> windows.suspicious_threads",
          "coletar_threads_suspeitas(dump)",
          ["Process", "PID", "TID", "Context", "Address", "VAD Path", "Note"],
          [[r.get("Process"), r.get("PID"), r.get("TID"), r.get("Context"),
            r.get("Address"), str(r.get("VAD Path", ""))[:70], str(r.get("Note", ""))[:60]]
           for r in memoria.get("threads_suspeitas", [])],
          limite=60)

    secao(elementos, "10. Manipuladores de Objetos (handles)",
          "Volatility 3 - plugin handles",
          "Handles abertos por processo (arquivos, chaves, portas) - auxilia na cadeia de prova.",
          "vol -f <memoria> windows.handles",
          "coletar_handles(dump)",
          ["PID", "Process", "Type", "Handle", "Detail"],
          [[r.get("PID"), r.get("Process"), r.get("Type"), r.get("Handle"),
            str(r.get("Detail", ""))[:90]] for r in memoria.get("handles", [])],
          limite=60)

    secao(elementos, "11. Privilégios dos Processos (privs)",
          "Volatility 3 - plugin privs",
          "Privilégios habilitados por processo (ex.: SeDebugPrivilege), usados em escalada de privilégios.",
          "vol -f <memoria> windows.privs",
          "coletar_privilegios(dump)",
          ["PID", "Process", "Privilege", "Attributes", "Enabled"],
          [[r.get("PID"), r.get("Process"), r.get("Privilege"), r.get("Attributes"),
            r.get("Enabled")] for r in memoria.get("privilegios", [])],
          limite=60)

    secao(elementos, "12. Variáveis de Ambiente (envars)",
          "Volatility 3 - plugin envars",
          "Variáveis de ambiente por processo; alterações suspeitas (PATH, TEMP) favorecem persistência.",
          "vol -f <memoria> windows.envars",
          "coletar_variaveis_ambiente(dump)",
          ["PID", "Process", "Variable", "Value"],
          [[r.get("PID"), r.get("Process"), r.get("Variable"), str(r.get("Value", ""))[:90]]
           for r in memoria.get("variaveis_ambiente", [])],
          limite=60)

    secao(elementos, "13. Serviços do Windows",
          "Volatility 3 - plugin svcscan",
          "Serviços registrados na memória (prova AM-09).",
          "vol -f <memoria> windows.svcscan",
          "coletar_servicos(dump)",
          ["Order", "PID", "Name", "State", "Type"],
          [[r.get("Order"), r.get("PID"), r.get("Name"), r.get("State"), r.get("Type")]
           for r in memoria.get("servicos", [])],
          limite=60)

    secao(elementos, "14. Arquivos Abertos em Memória",
          "Volatility 3 - plugin filescan",
          "Objetos de arquivo presentes na memória (inclui artefatos já deletados no disco).",
          "vol -f <memoria> windows.filescan",
          "coletar_arquivos_memoria(dump)",
          ["Offset", "Name"],
          [[r.get("Offset"), str(r.get("Name", ""))[:110]]
           for r in memoria.get("arquivos_memoria", [])],
          limite=60)

    elementos.append(PageBreak())
    elementos.append(Paragraph("PARTE II - ANÁLISE DE DISCO (THE SLEUTH KIT / PYTSK3)", S_SUB))
    elementos.append(Spacer(1, 6))

    secao(elementos, "15. Layout de Partições",
          "The Sleuth Kit - pytsk3.Volume_Info",
          "Estrutura de partições da imagem de disco.",
          "mmls <disco>",
          "get_volume_info(image_path)",
          ["Addr", "Start", "Length", "Description"],
          [[v.get("Addr"), v.get("Start"), v.get("Length"), v.get("Description")]
           for v in disco.get("volumes", [])])

    fs = disco.get("fs_info")
    if fs:
        elementos.append(Paragraph("16. Informações do Sistema de Arquivos", S_SEC))
        elementos.append(tabela([[k, str(v)] for k, v in fs.items()]))
        elementos.append(Spacer(1, 12))

    secao(elementos, "17. Estatísticas Gerais do Disco",
          "The Sleuth Kit - pytsk3 (agregação)",
          "Resumo quantitativo do conteúdo da imagem de disco.",
          f"fls -r -o {offset_disco} <disco> | wc -l",
          "coletores_disco.coletar_tudo()",
          ["Metrica", "Valor"],
          disco.get("disk_stats", []))

    secao(elementos, "18. Ferramentas de Invasão Detectadas no Disco",
          "The Sleuth Kit - pytsk3 + leitura direta (MD5/SHA256)",
          "Binários de pentest/offensive security encontrados na imagem, com hashes de integridade (prova AM-05).",
          f"fls -r -o {offset_disco} <disco>",
          "achar_ferramentas_ataque() + calcular_hashes()",
          ["Nome", "Caminho", "Tamanho", "MD5"],
          [[f.get("Name"), str(f.get("Path"))[:70], f.get("Size"), str(f.get("MD5"))]
           for f in disco.get("ferramentas_ataque", [])],
          limite=60)

    secao(elementos, "19. IOCs Extraídos do Conteúdo dos Arquivos",
          "The Sleuth Kit - pytsk3 + expressões regulares",
          "URLs, IPs, e-mails e caminhos encontrados no conteúdo dos arquivos da imagem.",
          f"fls -r -o {offset_disco} <disco> + strings",
          "extrair_iocs(fs_info, files)",
          ["Arquivo", "Tipo", "Valor"],
          [[str(i.get("Arquivo"))[:60], i.get("Tipo"), str(i.get("Valor"))[:80]]
           for i in disco.get("iocs", [])],
          limite=80)

    secao(elementos, "20. Distribuição por Extensão",
          "The Sleuth Kit - pytsk3 (agregação)",
          "Agrupamento dos arquivos por extensão.",
          f"fls -r -o {offset_disco} <disco>",
          "analyze_extensions(files)",
          ["Extensão", "Quantidade", "Tamanho Total (KB)"],
          disco.get("extensions", []))

    secao(elementos, "21. Top 20 Maiores Arquivos",
          "The Sleuth Kit - pytsk3 (agregação)",
          "Os 20 maiores arquivos da imagem.",
          f"fls -r -o {offset_disco} <disco>",
          "get_largest_files(files)",
          ["Nome", "Caminho", "Tamanho (bytes)", "Modificado"],
          disco.get("largest_files", []))

    secao(elementos, "22. Linha do Tempo por Ano (MAC)",
          "The Sleuth Kit - pytsk3 (agregação)",
          "Distribuição dos arquivos por ano de modificação.",
          f"fls -m / -o {offset_disco} <disco> > bodyfile && mactime -b bodyfile -d",
          "build_timeline_by_year(files)",
          ["Ano", "Quantidade de Arquivos"],
          disco.get("timeline_years", []))

    secao(elementos, "23. Diretórios Suspeitos",
          "The Sleuth Kit - pytsk3 (filtro por nome)",
          "Diretórios associados a áreas de risco (Temp, AppData, Prefetch, etc.).",
          f"fls -r -o {offset_disco} <disco>",
          "find_suspicious_dirs(files)",
          ["Nome", "Caminho", "Modificado"],
          disco.get("suspicious_dirs", []))

    secao(elementos, "24. Alternate Data Streams (ADS)",
          "The Sleuth Kit - pytsk3 (detecao de ':')",
          "Fluxos de dados ocultos no NTFS.",
          f"fls -r -o {offset_disco} <disco>",
          "find_ads(files)",
          ["Nome", "Caminho", "Tamanho"],
          disco.get("ads_files", []))

    secao(elementos, "25. Arquivos Ocultos",
          "The Sleuth Kit - pytsk3 (flag Hidden)",
          "Arquivos com atributo oculto.",
          f"fls -r -o {offset_disco} <disco>",
          "find_hidden_files(files)",
          ["Nome", "Caminho", "Tamanho", "Modificado"],
          disco.get("hidden_files", []))

    secao(elementos, "26. Arquivos Alocados (amostra recursiva)",
          "The Sleuth Kit - pytsk3.FS_Info.open_dir",
          "Amostra recursiva de arquivos/diretórios com timestamps MAC.",
          f"fls -r -o {offset_disco} <disco>",
          "walk_directory(fs_info, ...)",
          ["Nome", "Caminho", "Tipo", "Tamanho", "Modificado", "MD5"],
          [[f.get("Name"), str(f.get("Path"))[:70], f.get("Type"), f.get("Size"),
            f.get("Modified"), str(f.get("MD5"))[:16]] for f in disco.get("disk_files", [])],
          limite=80)

    secao(elementos, "27. Arquivos Deletados (recursivo)",
          "The Sleuth Kit - pytsk3 (TSK_FS_META_FLAG_UNALLOC)",
          "Arquivos deletados recuperáveis.",
          f"fls -rd -o {offset_disco} <disco>",
          "scan_deleted_files(fs_info, ...)",
          ["Caminho", "Inode", "Tamanho", "Tipo", "Modificado"],
          [[d.get("Path"), d.get("Inode"), d.get("Size"), d.get("Type"), d.get("Modified")]
           for d in disco.get("deleted_files", [])],
          limite=80)

    doc.build(elementos)
    return output_path
