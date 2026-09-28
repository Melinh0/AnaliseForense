import platform
from deteccao import CORRELACAO

def versao(pacote):
    try:
        from importlib.metadata import version
        return version(pacote)
    except Exception:
        return "?"


def ferramentas():
    return [
        ["Ferramenta", "Versão", "Função no laudo", "Como foi invocada"],
        ["Volatility 3", versao("volatility3"),
         "Análise da memória volátil: reconstrói estruturas do kernel "
         "(processos, sockets, serviços, VADs) direto do dump.",
         "API Python (construct_plugin), equivalente a CLI "
         "'vol -f <arquivo> <plugin>'"],
        ["The Sleuth Kit (pytsk3)", versao("pytsk3"),
         "Análise da imagem de disco sem montá-la: partições, sistema de "
         "arquivos, arquivos deletados, ocultos, ADS e conteúdo.",
         "API Python (Img_Info, FS_Info, open_dir, read_random), "
         "equivalente a CLIs 'mmls', 'fls', 'istat', 'icat'"],
        ["Python", platform.python_version(),
         "Orquestração da coleta, motor de regras AM-01..AM-10 e cálculo "
         "de hashes de integridade (modulos hashlib/md5, sha256).",
         "relatorio_forense.py (executável principal)"],
        ["ReportLab", versao("reportlab"),
         "Montagem do laudo em PDF (estilos, tabelas, capítulos).",
         "relatorio_pdf.py (build_pdf)"],
        ["Modos de acesso", "-",
         "Toda a análise é somente leitura: nenhuma mídia é alterada, "
         "montada em escrita ou executada.",
         "Leitura por offset/blocos via pytsk3 e carregamento do dump "
         "pelo Volatility"],
    ]


PIPELINE = [
    ["Etapa", "O que acontece", "Arquivo responsável", "Saída"],
    ["1. Aquisição",
     "Cópia bit-a-bit da memória física (memory.raw) e da imagem de disco "
     "(disk.dd). O laudo referência os arquivos por caminho, sem modificá-los.",
     "dados/", "Mídias de origem"],
    ["2. Integridade (antes)",
     "MD5 e SHA256 de cada mídia em uma única leitura, antes de qualquer "
     "plugin rodar.", "integridade.py", "Hash de referência"],
    ["3. Coleta",
     "14 plugins do Volatility 3 sobre a memória e varredura pytsk3 sobre o "
     "disco (partições, árvore de arquivos, conteúdo, hashes).",
     "coletores_memoria.py / coletores_disco.py", "Dicts memória/disco"],
    ["4. Normalização",
     "Valores ilegíveis do Volatility viram 'NAO-LEGIVEL' e as colunas são "
     "localizadas por nome (função coluna), para não depender de ordem.",
     "coletores_memoria.py", "Linhas de dicionario"],
    ["5. Regras AM-01..AM-10",
     "Cada regra é um predicado booleano sobre as fontes coletadas; quando "
     "verdadeiro gera uma lista de evidências (uma linha por ocorrência, com "
     "PID, caminho, IP ou hash).", "deteccao.py", "Lista de Achados"],
    ["6. Correlação e veredito",
     "As fontes que se apoiam no achado são listadas, a severidade é "
     "atribuida por critério e a conclusão pericial é escrita junto do "
     "comando CLI que reproduz a prova.", "deteccao.py", "Achados + veredito"],
    ["7. Integridade (depois) e laudo",
     "Novo MD5/SHA256 das mídias após a análise, comparado com o passo 2, e "
     "geração do PDF com todos os dados.",
     "integridade.py / relatorio_pdf.py", "relatorio_forense.pdf"],
]

SEVERIDADES = [
    ["Severidade", "Critério de atribuição", "Regras atuais"],
    ["CRÍTICO",
     "A evidência, sozinha, demonstra comprometimento ativo ou evasão de "
     "detecção (execução maliciosa, ocultação de processo, injeção de "
     "código). Não exige validação adicional para indicar incidente.",
     "AM-01, AM-02, AM-03, AM-10"],
    ["ALTO",
     "Evidência forte de preparação ou infraestrutura de ataque (conexão "
     "externa suspeita, ferramenta ofensiva no disco). Forte indício, mas "
     "requer cruzamento com outras fontes para fechar o caso.",
     "AM-04, AM-05"],
    ["MÉDIO",
     "Risco indireto, higiene de seguranca ou superfície de ataque. Não "
     "prova ataque por si; indica ponto que exige validação humana.",
     "AM-06, AM-07, AM-08, AM-09"],
    ["BAIXO",
     "Observação informativa sem impacto direto sobre a conclusão.",
     "Nenhuma regra atual (reservado)"],
]

VOLATILITY = [
    ["Plugin", "Mecanismo de detecção", "O que vira evidência", "Regra"],
    ["windows.pslist",
     "Percorre a lista duplamente encadeada PsActiveProcessHead no kernel e "
      "recupera cada estrutura EPROCESS (a referência \"oficial\" de processos "
     "ativos).",
     "PID, PPID, nome da imagem, threads, handles e tempo de criação.",
     "Base de AM-01, AM-02, AM-06"],
    ["windows.psxview",
     "Cruza pslist com varreduras independentes: psscan (pool scanning - "
     "procura a assinatura de EPROCESS em toda a memória, achando processos "
     "desanexados da lista) e thrdscan (procura de ETHREAD), alem de outras "
     "fontes.",
     "Colunas booleanas (pslist, psscan, thrdscan, csrss...) por PID; "
     "FALSE no pslist e TRUE no psscan/thrdscan = processo oculto.",
     "AM-02"],
    ["windows.cmdline",
     "Para cada EPROCESS lê o PEB do processo (ProcessParameters) e extrai "
     "a string CommandLine completa.",
     "Linha de comando integral por PID: interpretador, script e caminho "
     "de execução.", "AM-01, AM-06"],
    ["windows.netscan",
     "Varre o pool por estruturas _TCP_ENDPOINT / _UDP_ENDPOINT (não "
     "depende de API do sistema) e associa cada socket ao processo dono.",
     "Protocolo, endereços/portas locais e remotas, estado e dono (PID).",
     "AM-04, AM-07"],
    ["windows.malfind",
     "Varre os VADs (blocos de memória virtual) procurando regiões privadas "
     "com permissão de execução (PAGE_EXECUTE_READWRITE) que não possuem "
     "seção de arquivo associada.",
     "Intervalo [Start VPN - End VPN], proteção e processo - região "
     "executável injetada.", "AM-03"],
    ["windows.dlllist",
     "Lê a lista InLoadOrderModuleList do PEB.Ldr de cada processo (DLLs "
     "declaradas pelo próprio processo).",
     "Base, nome e caminho de cada DLL carregada (caminho fora do padrão "
     "confirma injeção).", "Anexo (corrobora AM-03)"],
    ["windows.ldrmodules",
     "Compara as três listas do PEB.Ldr (InLoad, InInit, InMem) com o "
     "mapeamento de arquivo no VAD; DLL mapeada no disco mas ausente de "
     "alguma lista está 'unlinked'.",
     "DLL presente em disco e ausente de InLoad/InInit/InMem.",
     "AM-10"],
    ["windows.hollowprocesses",
     "Compara a imagem do executável em disco com o conteúdo carregado na "
     "memória do processo (seção de imagem / entry point) e identifica "
     "substituicao da imagem original.",
     "Processo com imagem substituída (process hollowing / RunPE).",
     "AM-10"],
    ["windows.suspicious_threads",
     "Verifica o endereço de início (start address) de cada thread e "
     "confere se ele pertence a um módulo carregado ou a um VAD de arquivo.",
     "Thread cujo início cai em região privada/não mapeada (código "
     "injetado).", "AM-10"],
    ["windows.svcscan",
     "Localiza na memória as estruturas _SERVICE_RECORD (registro do SCM) e "
     "lê nome, estado, tipo e PID de cada serviço.",
     "Serviços RUNNING com nome e binário associado.", "AM-09"],
    ["windows.filescan",
     "Varre o pool por _FILE_OBJECT - objetos de arquivo existentes na "
     "memória, inclusive de arquivos já removidos no disco.",
     "Offset e caminho de arquivos abertos/mapeados.",
     "Anexo (complementa AM-08)"],
    ["windows.handles",
     "Enumera a ObjectTable.HandleTable de cada EPROCESS.",
     "Handles de arquivo, chave de registro e porta por processo "
     "(cadeia de prova).", "Anexo"],
    ["windows.privs",
     "Lê o token do processo (EPROCESS.Token -> _TOKEN.Privileges).",
     "Privilégios habilitados (ex.: SeDebugPrivilege) usados em "
     "escalada de privilégios.", "Anexo"],
    ["windows.envars",
     "Lê o bloco de ambiente do processo (PEB/ProcessParameters).",
     "Variáveis de ambiente (PATH, TEMP) usadas para persistência.",
     "Anexo"],
]

TSK = [
    ["API / flag do pytsk3", "Metadado lido", "O que vira evidência", "Regra"],
    ["pytsk3.Img_Info",
     "Leitura crua da imagem por blocos, sem montar o sistema de arquivos "
     "em escrita.", "Acesso aos bytes da mídia para todos os passos "
     "seguintes.", "Base"],
    ["pytsk3.Volume_Info",
     "Tabela de partições (MBR/GPT).",
     "Endereço, início, tamanho e descrição de cada partição.",
     "Seção 15"],
    ["pytsk3.FS_Info(offset=...)",
     "Cabecalho do sistema de arquivos e MFT (NTFS) / entradas de "
     "diretório, a partir do offset da partição.",
     "Tipo de FS (NTFS/FAT/ext), tamanho de bloco, inode raiz.",
     "Seção 16"],
    ["FS_Info.open_dir + walk_directory",
     "Entradas de diretório apontando para inodes; recursão por diretório "
     "até a profundidade limite.",
     "Árvore de arquivos com nome, tipo, tamanho e timestamps MAC "
     "(criado/modificado/acessado).", "Seções 20 a 27"],
    ["meta.flags & TSK_FS_META_FLAG_UNALLOC",
     "Bit de 'não alocado' na entrada de metadados - arquivo removido, cuja "
     "entrada não é mais referenciada pelo diretório.",
     "Arquivo deletado ainda recuperável (inode, tamanho, data).",
     "Seção 27"],
    ["meta.size == 0",
     "Campo de tamanho do metadado.",
     "Arquivo essencial com 0 bytes (truncado/removido).", "AM-08"],
    ["meta.mode & 0o1000 (bit H/K)",
     "Atributo oculto declarado no metadado (NTFS/FAT).",
     "Lista de arquivos ocultos para o usuário.", "Seção 25"],
    ["Nome contendo ':' (ADS)",
     "Entrada de diretório que aponta para um fluxo alternativo do NTFS "
     "(arquivo.ext:fluxo).",
     "Fluxos de dados ocultos no NTFS.", "Seção 24"],
    ["FS_Info.open().read_random()",
     "Conteúdo bruto do arquivo lido direto da mídia (sem executar nada).",
     "IOCs por expressão regular (URL, IPv4, e-mail, caminho Windows), "
     "hashes MD5/SHA256 e casamento da lista de ferramentas de ataque.",
     "AM-05 e seções 18/19"],
    ["meta.mtime / crtime / atime",
     "Campos de tempo do metadado (MAC).",
     "Timeline por ano e arquivos suspeitos por data.",
     "Seção 22"],
]

LIMITACOES = [
    "pslist reflete o estado da lista ativa do kernel: processos já "
    "finalizados legitimamente também podem aparecer apenas no psscan, "
    "então AM-02 é um indício de ocultação, não prova isolada de DKOM.",

    "O dono de um socket nem sempre é legível na memória (PID = "
    "NAO-LEGIVEL); nesse caso AM-04 sustenta-se no endereço de destino "
    "e nos IOCs do disco, e não na atribuição do processo.",

    "A baseline de serviços do AM-09 é uma lista heurística de serviços "
    "comuns do Windows: serviço customizado legítimo pode ser sinalizado e "
    "exige validação do caminho do binário antes de conclusão.",

    "Os IOCs de disco vêm de expressões regulares: podem haver falsos "
    "positivos (ex.: IP aparecendo em texto comum) e falsos negativos "
    "(conteúdo ofuscado/criptografado não casa com o padrão).",

    "A varredura de disco é limitada (profundidade de diretório, limite de "
    "arquivos e de tamanho por leitura) para manter o tempo de execução "
    "aceitável: a ausência de um arquivo na amostra não prova ausência na "
    "mídia inteira.",

    "Hashes de integridade de arquivo são calculados apenas para arquivos "
    "até 64 MB; arquivos maiores aparecem com MD5/SHA256 = '-'.",

    "A evidência técnica descreve o que existe na mídia, mas não "
    "estabelece autoria: identificar quem executou e por que exige "
    "validação humana, contexto adicional (logs, testemunhas, data da "
    "captura) e cadeia de custódia documentada.",
]


def cadeia_prova():
    return [["Regra", "Fontes que se cruzam para formar a cadeia de prova"]] + [
        [regra, ", ".join(fontes)] for regra, fontes in sorted(CORRELACAO.items())
    ]
