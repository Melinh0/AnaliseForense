import hashlib
import os
import re
from collections import Counter
from datetime import datetime

import pytsk3

SUSPICIOUS_DIRS = [
    "recycle.bin", "temp", "tmp", "appdata", "downloads",
    "programdata", "startup", "prefetch", "recent", "cache",
]

FERRAMENTAS_ATAQUE = [
    "evil-winrm", "mimikatz", "mimilib", "ncat", "netcat", "nc.exe",
    "plink", "putty", "psexec", "cain", "avalanche", "hydra", "john",
    "hashcat", "responder", "crackmapexec", "metasploit", "msfvenom",
    "cobalt", "empire", "stunnel", "tightvnc", "vncviewer", "winscp",
    "filezilla", "procdump", "prokarma", "unrar-nonfree", "pkexec",
    "chisel", "ligolo", "rubeus", "sharpdump", "sharphound",
]

PADROES_IOC = {
    "url": re.compile(r"https?://[^\s\"'<>]{4,120}", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,10}\b"),
    "caminho_windows": re.compile(r"[A-Za-z]:\\[^\s\"'<>|]{3,120}"),
}


def get_volume_info(image_path):
    img_info = pytsk3.Img_Info(image_path)
    volumes = []
    try:
        vs = pytsk3.Volume_Info(img_info)
        for part in vs:
            volumes.append({
                "Addr": part.addr,
                "Start": part.start,
                "Length": part.len,
                "Description": part.desc.decode("utf-8", "ignore") if part.desc else "N/A",
            })
    except Exception:
        volumes.append({
            "Addr": "N/A", "Start": 0, "Length": "N/A",
            "Description": "Imagem sem tabela de partição (sistema de arquivos direto)",
        })
    return volumes


def get_filesystem_info(image_path, offset=0):
    img_info = pytsk3.Img_Info(image_path)
    fs_info = pytsk3.FS_Info(img_info, offset=offset)
    info = fs_info.info
    ftype_map = {
        pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
        pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
        pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
        pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
        pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
        pytsk3.TSK_FS_TYPE_EXT2: "ext2",
        pytsk3.TSK_FS_TYPE_EXT3: "ext3",
        pytsk3.TSK_FS_TYPE_EXT4: "ext4",
        pytsk3.TSK_FS_TYPE_HFS: "HFS",
        pytsk3.TSK_FS_TYPE_ISO9660: "ISO9660",
        pytsk3.TSK_FS_TYPE_YAFFS2: "YAFFS2",
    }
    ftype = ftype_map.get(info.ftype, f"Desconhecido ({info.ftype})")
    total = info.block_size * info.block_count
    return {
        "Tipo de Sistema de Arquivos": ftype,
        "Tamanho do Bloco (bytes)": info.block_size,
        "Total de Blocos": info.block_count,
        "Tamanho Total (MB)": round(total / (1024 * 1024), 2),
        "Inode Raiz": info.root_inum,
    }


def abrir_fs(image_path, offset=0):
    img_info = pytsk3.Img_Info(image_path)
    return pytsk3.FS_Info(img_info, offset=offset)


def walk_directory(fs_info, directory, current_path="", max_depth=8, current_depth=0):
    results = []
    if current_depth > max_depth:
        return results
    try:
        for entry in directory:
            if entry.info.name is None:
                continue
            name = entry.info.name.name.decode("utf-8", "ignore")
            if name in (".", ".."):
                continue
            meta = entry.info.meta
            if meta is None:
                continue

            is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                ftype = "DIR"
            elif meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                ftype = "FILE"
            else:
                ftype = "OUTRO"

            full_path = current_path + "\\" + name if current_path else "\\" + name
            ext = os.path.splitext(name)[1].lower() if "." in name else "sem_extensao"

            def ts(v):
                return str(datetime.fromtimestamp(v))[:19] if v else "N/A"

            oculto = bool(meta.mode & 0o1000) if meta.mode else False

            results.append({
                "Name": name[:60],
                "Path": full_path,
                "Type": ftype,
                "Size": meta.size,
                "Created": ts(meta.crtime),
                "Modified": ts(meta.mtime),
                "Accessed": ts(meta.atime),
                "Deleted": "SIM" if is_deleted else "NÃO",
                "Hidden": "SIM" if oculto else "NÃO",
                "Extension": ext,
                "Inode": meta.addr,
                "IsADS": "SIM" if name.count(":") > 1 else "NÃO",
            })

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR and not is_deleted:
                try:
                    subdir = fs_info.open_dir(inode=meta.addr)
                    results.extend(walk_directory(fs_info, subdir, full_path, max_depth, current_depth + 1))
                except Exception:
                    pass
    except Exception:
        pass
    return results


def scan_deleted_files(fs_info, directory, current_path="", max_depth=8, current_depth=0, max_files=2000):
    deleted = []
    if current_depth > max_depth or len(deleted) >= max_files:
        return deleted
    try:
        try:
            entries = fs_info.open_dir(
                inode=directory.info.meta.addr if hasattr(directory, "info") else None,
                alloc=pytsk3.TSK_FS_META_FLAG_ALLOC | pytsk3.TSK_FS_META_FLAG_UNALLOC,
            )
        except Exception:
            entries = directory

        for entry in entries:
            if entry.info.name is None:
                continue
            name = entry.info.name.name.decode("utf-8", "ignore")
            if name in (".", ".."):
                continue
            meta = entry.info.meta
            if meta is None:
                continue

            is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            full_path = current_path + "\\" + name if current_path else "\\" + name

            if is_deleted:
                deleted.append({
                    "Path": full_path,
                    "Inode": meta.addr,
                    "Size": meta.size,
                    "Type": "DIR" if meta.type == pytsk3.TSK_FS_META_TYPE_DIR else "FILE",
                    "Modified": str(datetime.fromtimestamp(meta.mtime))[:19] if meta.mtime else "N/A",
                })

            if meta.type == pytsk3.TSK_FS_META_TYPE_DIR and not is_deleted:
                try:
                    subdir = fs_info.open_dir(inode=meta.addr)
                    deleted.extend(scan_deleted_files(
                        fs_info, subdir, full_path, max_depth, current_depth + 1, max_files
                    ))
                except Exception:
                    pass
    except Exception:
        pass
    return deleted


def ler_conteudo(fs_info, caminho, tamanho, limite=4 * 1024 * 1024):
    if not isinstance(tamanho, int) or tamanho <= 0:
        return b""
    try:
        fh = fs_info.open(caminho.replace("\\", "/"))
    except Exception:
        return b""
    leitura = min(tamanho, limite)
    try:
        return fh.read_random(0, leitura)
    except Exception:
        return b""


def calcular_hashes(fs_info, files, limite_arquivo=64 * 1024 * 1024):
    for f in files:
        if f["Type"] != "FILE" or not isinstance(f["Size"], int) or f["Size"] <= 0:
            f["MD5"] = "-"
            f["SHA256"] = "-"
            continue
        if f["Size"] > limite_arquivo:
            f["MD5"] = "-"
            f["SHA256"] = "-"
            continue
        conteudo = ler_conteudo(fs_info, f["Path"], f["Size"])
        if not conteudo:
            f["MD5"] = "-"
            f["SHA256"] = "-"
            continue
        f["MD5"] = hashlib.md5(conteudo).hexdigest()
        f["SHA256"] = hashlib.sha256(conteudo).hexdigest()
    return files


def extrair_iocs(fs_info, files, limite_arquivo=2 * 1024 * 1024, max_iocs=400):
    iocs = []
    for f in files:
        if len(iocs) >= max_iocs:
            break
        if f["Type"] != "FILE" or not isinstance(f["Size"], int) or f["Size"] <= 0:
            continue
        conteudo = ler_conteudo(fs_info, f["Path"], f["Size"], limite=limite_arquivo)
        if not conteudo:
            continue
        texto = conteudo.decode("latin-1", "ignore")
        for tipo, padrao in PADROES_IOC.items():
            for achado in set(padrao.findall(texto)):
                if tipo == "ipv4":
                    partes = achado.split(".")
                    if any(int(p) > 255 for p in partes):
                        continue
                    if achado.startswith(("127.", "0.", "255.255")):
                        continue
                iocs.append({"Arquivo": f["Path"], "Tipo": tipo, "Valor": achado})
                if len(iocs) >= max_iocs:
                    break
    return iocs


def achar_ferramentas_ataque(files):
    achados = []
    for f in files:
        if f["Type"] != "FILE":
            continue
        nome = f["Name"].lower()
        for ferramenta in FERRAMENTAS_ATAQUE:
            if ferramenta in nome:
                achados.append(f)
                break
    return achados


def analyze_extensions(files):
    counter = Counter()
    total_size = Counter()
    for f in files:
        if f["Type"] == "FILE":
            counter[f["Extension"]] += 1
            total_size[f["Extension"]] += f["Size"] if isinstance(f["Size"], int) else 0
    return [[ext, count, round(total_size[ext] / 1024, 2)]
            for ext, count in counter.most_common(20)]


def get_largest_files(files, limit=20):
    apenas = [f for f in files if f["Type"] == "FILE" and isinstance(f["Size"], int)]
    apenas.sort(key=lambda x: x["Size"], reverse=True)
    return [[f["Name"][:40], f["Path"][:60], f["Size"], f["Modified"]] for f in apenas[:limit]]


def find_suspicious_dirs(files):
    rows = []
    for f in files:
        if f["Type"] == "DIR" and any(sd in f["Path"].lower() for sd in SUSPICIOUS_DIRS):
            rows.append([f["Name"][:40], f["Path"][:80], f["Modified"]])
    return rows[:50]


def find_ads(files):
    return [[f["Name"][:50], f["Path"][:80], f["Size"]] for f in files if f["IsADS"] == "SIM"][:30]


def find_hidden_files(files):
    return [[f["Name"][:50], f["Path"][:80], f["Size"], f["Modified"]]
            for f in files if f["Hidden"] == "SIM" and f["Type"] == "FILE"][:50]


def build_timeline_by_year(files):
    counter = Counter()
    for f in files:
        if f["Type"] == "FILE" and f["Modified"] != "N/A":
            counter[f["Modified"][:4]] += 1
    return [[ano, count] for ano, count in sorted(counter.items())]


def coletar_tudo(image_path, offset=0, progresso=print):
    dados = {
        "volumes": [], "fs_info": None, "disk_files": [], "deleted_files": [],
        "disk_stats": [], "extensions": [], "largest_files": [], "timeline_years": [],
        "suspicious_dirs": [], "ads_files": [], "hidden_files": [],
        "ferramentas_ataque": [], "iocs": [],
    }
    try:
        progresso("Lendo layout de partições...")
        dados["volumes"] = get_volume_info(image_path)
    except Exception as exc:
        progresso(f"  erro: {exc}")

    try:
        progresso("Lendo informações do sistema de arquivos...")
        dados["fs_info"] = get_filesystem_info(image_path, offset=offset)
    except Exception as exc:
        progresso(f"  erro: {exc}")

    fs_info = None
    try:
        fs_info = abrir_fs(image_path, offset=offset)
    except Exception as exc:
        progresso(f"  erro ao abrir FS: {exc}")

    if fs_info is None:
        return dados

    progresso("Listando arquivos (recursivo)...")
    dados["disk_files"] = walk_directory(fs_info, fs_info.open_dir(path="/"))

    progresso("Procurando arquivos deletados...")
    dados["deleted_files"] = scan_deleted_files(fs_info, fs_info.open_dir(path="/"))

    progresso("Calculando hashes (MD5/SHA256)...")
    dados["disk_files"] = calcular_hashes(fs_info, dados["disk_files"])

    progresso("Extraindo IOCs (URLs, IPs, e-mails)...")
    dados["iocs"] = extrair_iocs(fs_info, dados["disk_files"])

    progresso("Procurando ferramentas de ataque...")
    dados["ferramentas_ataque"] = achar_ferramentas_ataque(dados["disk_files"])

    progresso("Gerando estatísticas...")
    arquivos = [f for f in dados["disk_files"] if f["Type"] == "FILE"]
    dados["disk_stats"] = [
        ["Total de arquivos", len(arquivos)],
        ["Total de diretórios", sum(1 for f in dados["disk_files"] if f["Type"] == "DIR")],
        ["Total de arquivos deletados", len(dados["deleted_files"])],
        ["Total de arquivos ocultos", sum(1 for f in arquivos if f["Hidden"] == "SIM")],
        ["Total de Alternate Data Streams (ADS)", sum(1 for f in dados["disk_files"] if f["IsADS"] == "SIM")],
        ["Total de IOCs extraídos", len(dados["iocs"])],
        ["Tamanho total dos arquivos (MB)",
         round(sum(f["Size"] for f in arquivos if isinstance(f["Size"], int)) / (1024 * 1024), 2)],
    ]
    dados["extensions"] = analyze_extensions(dados["disk_files"])
    dados["largest_files"] = get_largest_files(dados["disk_files"])
    dados["timeline_years"] = build_timeline_by_year(dados["disk_files"])
    dados["suspicious_dirs"] = find_suspicious_dirs(dados["disk_files"])
    dados["ads_files"] = find_ads(dados["disk_files"])
    dados["hidden_files"] = find_hidden_files(dados["disk_files"])
    return dados
