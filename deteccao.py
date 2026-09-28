from dataclasses import dataclass, field

from coletores_memoria import coluna

SEVERIDADES = ("CRÍTICO", "ALTO", "MÉDIO", "BAIXO")

PROCESSOS_LOJA = ("wscript", "cscript", "mshta", "powershell", "pwsh",
                  "rundll32", "regsvr32", "certutil", "cmd", "msiexec")

EXTENSOES_MALIGNAS = (".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1",
                      ".bat", ".cmd", ".scr", ".lnk", ".dll", ".exe")

CAMINHOS_RISCO = ("\\temp\\", "\\tmp\\", "\\temporary internet files",
                  "\\appdata\\local\\temp", "\\appdata\\roaming\\",
                  "\\users\\public\\", "\\programdata\\", "\\downloads\\")

PORTAS_EXPOSTAS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 5900: "VNC",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS", 1234: "porta comum de backdoor",
    4444: "porta comum de shell reversa", 5555: "porta comum de backdoor",
}

FERRAMENTAS_SEGURANCA = ("sysmon", "procmon", "procexp", "tcpview", "autoruns",
                         "wireshark", "x64dbg", "ollydbg", "idaq", "idag")

SERVICOS_BASELINE = {
    "spooler", "spldr", "shellhwdetection", "sessionenv", "sens", "seclogon",
    "schedule", "samss", "rspndr", "rpcss", "rpceptmapper",
    "rpclocator", "rdyboost", "rdprefmp", "rdpendd", "rdpdr", "remoteRegistry",
    "remoteregistry", "rasman", "nla", "netlogon", "mpssvc", "lanmanserver",
    "lanmanworkstation", "dhcp", "dnscache", "eventlog", "eventsystem",
    "cryptsvc", "laser", "lsass", "dcomlaunch", "plugplay", "power", "dwm",
    "themes", "uxsms", "audioendpointbuilder", "audiosrv", "bits", "browser",
    "camsvc", "cdpsvc", "clipsvc", "comsysapp", "coremessaging", "cscservice",
    "defwatch", "diagnosticshub.standardcollector.service", "difsvc",
    "dmwappushservice", "dot3svc", "dps", "emdx", "gpsvc", "hidserv", "icssvc",
    "ikeext", "ipnat", "kmisc", "lltdsrv", "mdmxsvc", "mmcss", "msiscsi",
    "napagent", "netbt", "netman", "netprofm", "nsi", "ntds", "orev",
    "p2pimsvc", "pnrpsvc", "polagent", "powershell", "pipelsvc", "profsvc",
    "rasauto", "rasringe", "remoteaccess", "rdsacctmanager", "rdsarbiter",
    "rdsremotedesktop", "sessionenv", "sharedaccess", "sharedaccess_",
    "shellhwdetection", "sppsvc", "ssdpsrv", "statefulinspection", "stisvc",
    "svchost", "swprv", "sysmain", "systemeventsbroker", "tabctns",
    "tapisrv", "termervice", "termservice", "themes", "tickbroker",
    "tokenbroker", "upnphost", "usermanager", "userspace", "vmicvss",
    "vss", "w32time", "wbengine", "wcncsvc", "wdicsvc",
    "webclient", "wecsvc", "wephostsvc", "wersvc", "wfdsconnservice",
    "wlanautoconfig", "wlansvc", "wmiapapsrv", "wmiaprve", "wmidfs",
    "wmisvc", "wpc", "wscsvc", "wsearch", "wuauserv", "wudfsvc", "xboxgip",
    "xblauthmanager", "xblgamesave", "xboxnetapi", "appinfo",
    "brokerinfrastructure", "clipcap", "corewidgetdeployment",
    "deviceassociation", "devquerybroker", "diagnosticpolicy",
    "directexperience", "dmwappushservice_", "dot3svc_", "dps_", "drvfs",
    "dsmvc", "dusmsvc", "eam", "edgeupdate", "edgetransport", "embeddedmode",
    "fdphost", "fhmanagersvc", "fontcache", "frame_server", "gupdate",
    "heterotriaggregation", "hvkbservice", "installservice", "iphlpsvc",
    "jdk", "localpush", "lpasvc", "lsm", "mpssvc_", "msdpmsvc", "msoidsvc",
    "netsetupsvc", "notifsystem", "nutagent", "omniserv", "ose",
    "perceptionsimulation", "phone svc", "pbs", "qwave", "rasman_",
    "rdbss", "rdyboost_", "resvc", "rhoindex", "rise", "rsoe",
    "sensorservice", "sentinel", "seriousshutdown", "sgpca", "sgrmbroker",
    "sharedaccess__", "sharerecovery", "smphost", "smps", "srmsvc",
    "ssdpsrv_", "ssh-agent", "stisvc_", "storagessvc", "sysmatic", "tabletinputservice",
    "taptunsvc", "tbs", "teamviewer", "trustedinstaller", "ui0detect",
    "umpnpmgr", "unistore", "upnphost_", "userdata", "usermgrsvc",
    "vac", "vds", "vmicheartbeat", "vmicguestinterface", "vmicshutdown",
    "vmictimesync", "vmicvmsession", "vmkbd", "vmmouse", "vmvss", "vncserver",
    "volmgr", "vss_", "w32time", "walletservice", "wbiosrvc", "wcnfs",
    "wdsvc", "wecsvc_", "wia_", "winmgmt", "wisvc", "wlanuuidsvc", "wlpasvc",
    "wmiiss", "wmpnetworksvc", "wmsvc", "wncsvc", "wpcmonsvc", "wpax",
    "wsearchsvc", "wslservice", "wswp", "wudfs", "xboxes",
    "bam", "bindflt", "bowser", "cng", "condrv", "ddacelsys", "dfsc",
    "disk", "evol", "fastfat", "fileinfo", "fltmgr", "fvevol", "hdaudbus",
    "hpet", "http", "iastor", "intelppm", "ksecdd", "ksecpkg", "lwfio",
    "monitor", "mountmgr", "mpsdrv", "msrpc", "mup", "ndis", "ndisuio",
    "netbt", "netio", "nsiproxy", "ntp", "parport", "partmgr", "pcw",
    "peauth", "pmx", "rasacd", "rdbss_", "rfcomm", "rpcx", "sbp2port",
    "scfilter", "scsiport", "sdbus", "secdrv", "sentineldriver", "serenum",
    "serial", "sfloppy", "sftdisk", "smb", "sr", "srv", "srvnet", "stornvme",
    "swenum", "tcpip", "tcpipreg", "tdx", "termdd", "tunnel", "uaspstor",
    "udfs", "umpass", "vdrvroot", "volmgrx", "vpci", "vsmraid", "wdf01000",
    "wfplwfs", "wimmount", "wisvc_", "wmbus01", "ws2ifsl", "wudfpf",
    "netwtw", "rtwlanu", "athw", "bthpp", "usbvideo", "usbxhci",
    "acpi", "afd", "aelookupsvc", "appmgmt", "bfe", "beep", "clfs", "csc",
    "certpropsvc", "diagtrack", "fdrespub", "msfs", "netbios", "nlasvc",
    "npfs", "null", "pcasvc", "policyagent", "protectedstorage", "psched",
    "rdpcdd", "rdpencdd", "trkwks", "umrdpservice", "vgasave",
    "wanarpv6", "wdiservicehost", "wfpLwf", "windefend",
    "winhttpautoproxysvc", "winrm", "amdxata", "atapi", "blbdrive", "cdrom",
    "discache", "hwpolicy", "intelide", "lltdio", "lmhosts", "luafv",
    "mrxsmb", "mrxsmb10", "mrxsmb20", "msisadrv", "mssmbios", "pci", "srv2",
    "storflt", "volsnap",
}


@dataclass
class Achado:
    id: str
    titulo: str
    severidade: str
    categoria: str
    evidencias: list = field(default_factory=list)
    correlacao: list = field(default_factory=list)
    ferramenta: str = ""
    conclusao: str = ""


def _privado(ip):
    if not ip or ip in ("*", "-", "::", "0.0.0.0", "255.255.255.255"):
        return True
    if ip.startswith(("fe80", "127.", "0.", "169.254.")):
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        segundo = ip.split(".")[1]
        if segundo.isdigit() and 16 <= int(segundo) <= 31:
            return True
    return False


def _pids_pslist(dados_mem):
    pids = set()
    for row in dados_mem.get("processos", []):
        try:
            pids.add(int(float(str(row.get("PID", "0")))))
        except (TypeError, ValueError):
            continue
    return pids


def _nome_processo(dados_mem):
    nomes = {}
    for row in dados_mem.get("processos", []):
        try:
            nomes[int(float(str(row.get("PID", "0"))))] = str(row.get("ImageFileName", "?"))
        except (TypeError, ValueError):
            continue
    return nomes


def am01_scripts_suspensos(dados_mem):
    """Execucao de scripts/interpretes a partir de pastas de risco."""
    achados = []
    for row in dados_mem.get("cmdlines", []):
        processo = str(coluna(row, "Process", "ImageFileName"))
        args = str(coluna(row, "Args", "Arguments", "Command"))
        pid = str(coluna(row, "PID"))
        baixo = processo.lower()
        alvo = args.lower()
        if not any(p in baixo for p in PROCESSOS_LOJA):
            continue
        em_risco = any(c in alvo for c in CAMINHOS_RISCO)
        ext_suspeita = any(e in alvo for e in EXTENSOES_MALIGNAS)
        if em_risco and ext_suspeita:
            achados.append(f"PID {pid} :: {processo} {args}")
    return achados


def am02_processos_ocultos(dados_mem):
    """Processos visiveis em psscan/thrdscan mas ausentes do pslist."""
    agregado = {}
    for row in dados_mem.get("psxview", []):
        pid = str(coluna(row, "PID"))
        nome = str(coluna(row, "Name", "ImageFileName"))
        flags = {k.lower(): str(v).lower() == "true" for k, v in row.items()
                 if k not in ("PID", "Name", "Offset", "Create Time", "Exit Time",
                              "ImageFileName", "CreateTime", "ExitTime", "Offset(Virtual)")}
        item = agregado.setdefault((pid, nome), {})
        for k, v in flags.items():
            item[k] = item.get(k, False) or v

    pids_ativos = _pids_pslist(dados_mem)
    ocultos = []
    for (pid, nome), flags in agregado.items():
        no_pslist = flags.get("pslist", False)
        no_pool = flags.get("psscan", False)
        no_thrd = flags.get("thrdscan", False)
        try:
            pid_int = int(float(pid))
        except (TypeError, ValueError):
            pid_int = None
        if (no_pool or no_thrd) and not no_pslist:
            origem = "psscan" if no_pool else "thrdscan"
            ocultos.append(f"PID {pid} :: {nome} (visto em {origem}, ausente no pslist)")

    injetados = set()
    for row in dados_mem.get("injecoes", []):
        try:
            injetados.add(int(float(str(coluna(row, "PID")))))
        except (TypeError, ValueError):
            continue
    for pid_int in sorted(injetados - pids_ativos):
        ocultos.append(f"PID {pid_int} :: processo com região injetada que não existe no pslist")

    vistos = set()
    unicos = []
    for linha in ocultos:
        chave = linha.split(" (")[0]
        if chave not in vistos:
            vistos.add(chave)
            unicos.append(linha)
    return unicos


def am03_injecao_codigo(dados_mem):
    """Regioes executaveis sem correspondencia em arquivo (malfind)."""
    linhas = []
    for row in dados_mem.get("injecoes", []):
        protecao = str(coluna(row, "Protection", "Protect"))
        if "EXECUTE" not in protecao.upper():
            continue
        pid = str(coluna(row, "PID"))
        processo = str(coluna(row, "Process", "ImageFileName"))
        inicio = str(coluna(row, "Start VPN", "Start"))
        fim = str(coluna(row, "End VPN", "End"))
        linhas.append(f"PID {pid} :: {processo} [{inicio} - {fim}] {protecao}")
    return linhas


def am04_conexoes_externas(dados_mem, iocs_disco=None):
    """Conexoes para fora da rede privada (possivel C2), com dono ilegivel."""
    iocs_disco = iocs_disco or []
    ips_disco = {i["Valor"] for i in iocs_disco if i["Tipo"] == "ipv4"}
    linhas = []
    for row in dados_mem.get("rede", []):
        destino = str(coluna(row, "ForeignAddr", "Remote Address"))
        if _privado(destino) or destino == "NAO-LEGIVEL":
            continue
        estado = str(coluna(row, "State"))
        if estado in ("LISTENING",):
            continue
        porta_r = str(coluna(row, "ForeignPort", "Remote Port"))
        if porta_r in ("0", "-", "NAO-LEGIVEL"):
            continue
        proto = str(coluna(row, "Proto", "Protocol"))
        origem = str(coluna(row, "LocalAddr", "Local Address"))
        porta_l = str(coluna(row, "LocalPort", "Local Port"))
        pid = str(coluna(row, "PID"))
        dono = str(coluna(row, "Owner", "Process"))
        marcador = " [IP TAMBÉM NO DISCO]" if destino in ips_disco else ""
        linhas.append(
            f"{proto} {origem}:{porta_l} -> {destino}:{porta_r} [{estado}] "
            f"PID={pid} dono={dono}{marcador}"
        )
    vistos = set()
    unicos = []
    for l in linhas:
        if l not in vistos:
            vistos.add(l)
            unicos.append(l)
    return unicos


def am05_ferramentas_ataque(dados_disco):
    """Ferramentas de invasao presentes na imagem de disco."""
    linhas = []
    for f in dados_disco.get("ferramentas_ataque", []):
        linhas.append(
            f"{f['Path']} ({f['Size']} bytes) MD5={f.get('MD5','-')} SHA256={f.get('SHA256','-')}"
        )
    return linhas


def am06_mascaramento(dados_mem):
    """Binarios de seguranca/ferramentas fora dos caminhos padrao do Windows."""
    linhas = []
    for row in dados_mem.get("cmdlines", []):
        args = str(coluna(row, "Args", "Arguments", "Command"))
        pid = str(coluna(row, "PID"))
        processo = str(coluna(row, "Process", "ImageFileName"))
        if not args:
            continue
        caminho = args.split(" ")[0].strip('"')
        nome_base = caminho.split("\\")[-1].lower().replace(".exe", "")
        if not any(f in nome_base for f in FERRAMENTAS_SEGURANCA):
            continue
        padrao = caminho.lower().startswith(("c:\\windows\\system32", "c:\\program files"))
        if not padrao:
            linhas.append(f"PID {pid} :: {processo} executando de {caminho}")
    return linhas


def am07_superficie_ataque(dados_mem):
    """Servicos de acesso remoto/exposição escutando na imagem."""
    linhas = []
    for row in dados_mem.get("rede", []):
        if str(coluna(row, "State")) != "LISTENING":
            continue
        try:
            porta = int(float(str(coluna(row, "LocalPort", "Local Port"))))
        except (TypeError, ValueError):
            continue
        if porta not in PORTAS_EXPOSTAS:
            continue
        dono = str(coluna(row, "Owner", "Process"))
        proto = str(coluna(row, "Proto", "Protocol"))
        local = str(coluna(row, "LocalAddr", "Local Address"))
        linhas.append(f"{proto} {local}:{porta} ({PORTAS_EXPOSTAS[porta]}) dono={dono}")
    vistos = set()
    unicos = []
    for l in linhas:
        if l not in vistos:
            vistos.add(l)
            unicos.append(l)
    return unicos


def am08_arquivos_truncados(dados_disco):
    """Arquivos de 0 bytes em diretorios criticos (possivel exclusao/truncamento)."""
    linhas = []
    for f in dados_disco.get("disk_files", []):
        if f["Type"] == "FILE" and f["Size"] == 0:
            linhas.append(f"{f['Path']} (0 bytes, modificado {f['Modified']})")
    return linhas


def am09_servicos_fora_baseline(dados_mem):
    """Servicos RUNNING que nao pertencem a baseline comum do Windows."""
    conhecidos = {s.lower() for s in SERVICOS_BASELINE}
    linhas = []
    vistos = set()
    for row in dados_mem.get("servicos", []):
        estado = str(coluna(row, "State", "Status"))
        if "RUNNING" not in estado.upper():
            continue
        nome = str(coluna(row, "Name", "ServiceName"))
        if nome.lower() in conhecidos or nome in ("N/A", ""):
            continue
        if nome in vistos:
            continue
        vistos.add(nome)
        pid = str(coluna(row, "PID"))
        caminho = str(coluna(row, "Path", "ServicePath", padrao="-"))
        linhas.append(f"{nome} (PID {pid}, {estado}) {caminho}")
    return linhas


def am10_evasao_avancada(dados_mem):
    """Process hollowing, threads em regiao nao mapeada e DLLs desvinculadas."""
    linhas = []
    for row in dados_mem.get("process_hollowing", []):
        pid = str(coluna(row, "PID"))
        processo = str(coluna(row, "Process", "ImageFileName"))
        notas = str(coluna(row, "Notes", "Note"))
        linhas.append(f"HOLLOWING :: PID {pid} :: {processo} :: {notas}")
    for row in dados_mem.get("threads_suspeitas", []):
        pid = str(coluna(row, "PID"))
        processo = str(coluna(row, "Process", "ImageFileName"))
        tid = str(coluna(row, "TID"))
        endereco = str(coluna(row, "Address"))
        vad = str(coluna(row, "VAD Path", "VadPath"))
        nota = str(coluna(row, "Note", "Notes"))
        linhas.append(
            f"THREAD SUSPEITA :: PID {pid} ({processo}) TID {tid} @ {endereco} "
            f"VAD={vad} :: {nota}"
        )
    for row in dados_mem.get("dlls_ocultas", []):
        em_carga = str(coluna(row, "InLoad")).lower() == "true"
        em_init = str(coluna(row, "InInit")).lower() == "true"
        em_mem = str(coluna(row, "InMem")).lower() == "true"
        caminho = str(coluna(row, "MappedPath", "MappedName"))
        if not caminho or caminho == "-":
            continue
        baixo = caminho.lower()
        if baixo.endswith((".mui", ".fon", ".exe")):
            continue
        if baixo.startswith(("\\windows\\system32", "\\windows\\syswow64",
                             "\\windows\\fonts", "\\windows\\winsxs")):
            continue
        if not (em_carga and em_init and em_mem):
            faltando = []
            if not em_carga:
                faltando.append("InLoad")
            if not em_init:
                faltando.append("InInit")
            if not em_mem:
                faltando.append("InMem")
            linhas.append(
                f"DLL DESVINCULADA :: PID {coluna(row, 'Pid')} :: {caminho} "
                f"ausente em {','.join(faltando)}"
            )
    return linhas




def analisar(dados_mem, dados_disco):
    achados = []

    iocs = dados_disco.get("iocs", []) if dados_disco else []

    regras = [
        ("AM-01", "Execução de script suspeito em pasta de risco", "CRÍTICO",
         "Processamento", lambda: am01_scripts_suspensos(dados_mem),
         "vol -f <memoria> windows.cmdline",
         "Interpreter de script (wscript/cscript/rundll32) executou arquivo .js/.vbs "
         "a partir de pasta de temporização do navegador/usuário: atividade clássica de "
         "dropper iniciado por anexo ou download."),
        ("AM-02", "Processos ocultos/ausentes da lista ativa", "CRÍTICO",
         "Ocultação de processos", lambda: am02_processos_ocultos(dados_mem),
         "vol -f <memoria> windows.psxview",
         "Processos encontrados na varredura de pool (psscan) ou de threads (thrdscan) "
         "mas ausentes do pslist: indício de ocultação (DKOM) ou de processo já finalizado "
         "que permanece na memória - forte indício de atividade maliciosa."),
        ("AM-03", "Injeção de código em região executável", "CRÍTICO",
         "Injeção de código", lambda: am03_injecao_codigo(dados_mem),
         "vol -f <memoria> windows.malfind",
         "Regiões de memória com permissão de execução que não correspondem a arquivo em "
         "disco (PAGE_EXECUTE_READWRITE): vetor clássico de injeção de código. Quando o PID "
         "também aparece como oculto (AM-02), a cadeia de prova fica completa."),
        ("AM-04", "Conexões externas ativas (possível C2)", "ALTO",
         "Rede", lambda: am04_conexoes_externas(dados_mem, iocs),
         "vol -f <memoria> windows.netscan",
         "Comunicação com endereços fora da rede privada, com dono do processo ilegível em "
         "vários casos: compatível com canal de comando e controle (C2)."),
        ("AM-05", "Ferramentas de invasão no disco", "ALTO",
         "Disco", lambda: am05_ferramentas_ataque(dados_disco),
         "fls -r -o 0 <disco> + leitura direta dos arquivos (MD5/SHA256)",
         "Presença de ferramentas de pentest/offensive security na imagem, indicando que a "
         "máquina foi usada (ou preparada) como estação de ataque."),
        ("AM-06", "Binário executando fora do caminho padrão (mascaramento)", "MÉDIO",
         "Persistência/Mascaramento", lambda: am06_mascaramento(dados_mem),
         "vol -f <memoria> windows.cmdline",
         "Ferramenta de seguranca/monitoramento executada de caminho incomum "
         "(ex.: C:\\Windows\\<nome>.exe): possível binário mascarado pelo atacante."),
        ("AM-07", "Serviços de acesso remoto expostos", "MÉDIO",
         "Superfície de ataque", lambda: am07_superficie_ataque(dados_mem),
         "vol -f <memoria> windows.netscan",
         "Portas de acesso remoto (RDP/SMB/WinRM/VNC/etc.) em escuta: ampliam a superfície "
         "de ataque e são o alvo usual de exploração e movimento lateral."),
        ("AM-08", "Arquivos truncados/removidos na imagem", "MÉDIO",
         "Integridade do disco", lambda: am08_arquivos_truncados(dados_disco),
         "fls -r -o 0 <disco>",
         "Binários essenciais com 0 bytes: compatível com truncamento, remoção ou "
         "manipulação da imagem - exige verificação de integridade."),
        ("AM-09", "Serviços ativos fora da baseline", "MÉDIO",
         "Persistência", lambda: am09_servicos_fora_baseline(dados_mem),
         "vol -f <memoria> windows.svcscan",
         "Serviços em execução que não constam da baseline comum do Windows: candidatos a "
         "serviço persistente malicioso (validar caminho do binário)."),
        ("AM-10", "Evasão avançada: hollowing, threads suspeitas e DLLs desvinculadas",
         "CRÍTICO", "Evasão de detecção",
         lambda: am10_evasao_avancada(dados_mem),
         "vol -f <memoria> windows.hollowprocesses | windows.suspicious_threads | windows.ldrmodules",
         "Imagem de processo substituída (hollowing), threads iniciando em endereço sem "
         "módulo correspondente e DLLs presentes no disco mas ausentes das listas de carga: "
         "três técnicas de evasão que, somadas a AM-02 e AM-03, fecham a cadeia de prova de "
         "carregamento de código malicioso."),
    ]

    for id_, titulo, sev, categoria, funcao, ferramenta, conclusao in regras:
        try:
            evidencias = funcao()
        except Exception as exc:
            evidencias = [f"falha na regra: {exc}"]
        if not evidencias:
            continue
        correlacao = _correlacionar(id_, dados_mem, dados_disco)
        achados.append(Achado(
            id=id_, titulo=titulo, severidade=sev, categoria=categoria,
            evidencias=evidencias, correlacao=correlacao,
            ferramenta=ferramenta, conclusao=conclusao,
        ))

    achados.sort(key=lambda a: SEVERIDADES.index(a.severidade))
    return achados


CORRELACAO = {
    "AM-01": ["windows.cmdline", "windows.pslist", "disco (pastas de usuário)"],
    "AM-02": ["windows.psxview (pslist x psscan/thrdscan)", "windows.pslist",
              "windows.malfind", "windows.ldrmodules"],
    "AM-03": ["windows.malfind", "windows.pslist x windows.psxview (AM-02)",
              "windows.suspicious_threads (AM-10)", "windows.hollowprocesses (AM-10)"],
    "AM-04": ["windows.netscan", "windows.pslist (owner ilegível)", "IOCs do disco (AM-05)"],
    "AM-05": ["disco (fls/pytsk)", "hashes MD5/SHA256", "IOCs extraídos"],
    "AM-06": ["windows.cmdline (caminho do executável)"],
    "AM-07": ["windows.netscan (LISTENING)", "windows.pslist (dono da porta)"],
    "AM-08": ["disco (metadados de tamanho/MAC)"],
    "AM-09": ["windows.svcscan", "windows.pslist (PID do serviço)"],
    "AM-10": ["windows.hollowprocesses", "windows.suspicious_threads",
              "windows.ldrmodules", "windows.malfind (AM-03)", "windows.pslist"],
}


def _correlacionar(id_, dados_mem, dados_disco):
    """Cadeia de prova: quais fontes se apoiam mutuamente neste achado."""
    return CORRELACAO.get(id_, [])


def resumo_severidades(achados):
    contagem = {s: 0 for s in SEVERIDADES}
    for a in achados:
        contagem[a.severidade] = contagem.get(a.severidade, 0) + 1
    return contagem
