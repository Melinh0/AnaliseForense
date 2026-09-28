# AnaliseForense

Analise forense automatizada de imagem de memoria (Volatility 3) e de disco
(The Sleuth Kit / pytsk3) com deteccao de indicios de ameaca e relatorio PDF
que abre com o capitulo **Metodologia** (como as evidencias sao formadas,
como Volatility/TSK detectam, ferramentas e integridade das midias) seguido
do capitulo **Evidencias e Indicios de Ameacas**.

## Estrutura

| Arquivo | Funcao |
| --- | --- |
| `relatorio_forense.py` | Executavel principal (coleta + deteccao + PDF) |
| `coletores_memoria.py` | Plugins do Volatility 3 (pslist, cmdline, netscan, malfind, psxview, ldrmodules, hollowprocesses, suspicious_threads, svcscan, filescan, dlllist, handles, privs, envars) |
| `coletores_disco.py` | pytsk3: particoes, arquivos, deletados, hashes MD5/SHA256, IOCs, ferramentas de ataque |
| `deteccao.py` | Motor de regras AM-01..AM-10 com evidencias, correlacao entre fontes e conclusao |
| `metodologia.py` | Conteudo do capitulo de metodologia (ferramentas, pipeline, mecanismos Volatility/TSK, limitacoes) |
| `integridade.py` | Hash MD5/SHA256 das midias antes e depois da analise (prova de nao adulteracao) |
| `relatorio_pdf.py` | Montagem do PDF (Cap. 0 de metodologia, Cap. 1 de provas + anexos por ferramenta) |
| `data/` | Imagens forenses e saidas (**nao versionados**) |

## Uso

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt

# Coloque as imagens em data/memory.raw e data/disk.dd e execute:
.\.venv\Scripts\python.exe relatorio_forense.py
```

Saidas:

- `data/relatorios/relatorio_forense.pdf` - relatorio completo
- `data/cache/*.pkl` - cache da coleta (use `--sem-cache` para reexecutar tudo)

Opcoes: `--memoria`, `--disco`, `--offset`, `--saida`, `--sem-cache`.

## Metodologia

O PDF abre com o **Capitulo 0 - Metodologia e fundamentacao das evidencias**,
que responde como o laudo e construido:

| Secao | Conteudo |
| --- | --- |
| 0.1 | Ferramentas utilizadas, versao de cada uma e como foram invocadas |
| 0.2 | Integridade das midias (hash antes e depois da analise) |
| 0.3 | Pipeline de formacao de uma evidencia (aquisicao -> coleta -> regra -> correlacao) |
| 0.4 | Criterios de severidade (CRITICO/ALTO/MEDIO/BAIXO) |
| 0.5 | Mecanismo de deteccao de cada plugin do Volatility 3 (estrutura varrida) |
| 0.6 | Mecanismo de deteccao de cada API/flag do The Sleuth Kit (metadado lido) |
| 0.7 | Cadeia de prova: quais fontes se cruzam em cada regra |
| 0.8 | Limitacoes do metodo e risco de falsos positivos |

O **Capitulo 1** traz os achados AM-01..AM-10 e as Partes I/II os anexos de
memoria e disco.

## Integridade das midias

Para provar que `data/memory.raw` e `data/disk.dd` nao foram adulterados,
`integridade.py` calcula MD5 e SHA256 (unica leitura, em blocos):

1. **antes** de qualquer plugin do Volatility ou varredura TSK rodar;
2. **depois** que a deteccao termina, antes de gerar o PDF.

As duas leituras sao comparadas e o resultado (`INALTERADA` / `ALTERADA`)
aparece na capa e na secao 0.2 do laudo.

## Achados (regras AM)

| ID | Sev. | Titulo |
| --- | --- | --- |
| AM-01 | CRITICO | Execucao de script suspeito em pasta de risco |
| AM-02 | CRITICO | Processos ocultos/ausentes da lista ativa |
| AM-03 | CRITICO | Injecao de codigo em regiao executavel |
| AM-10 | CRITICO | Evasao avancada: hollowing, threads suspeitas e DLLs desvinculadas |
| AM-04 | ALTO | Conexoes externas ativas (possivel C2) |
| AM-05 | ALTO | Ferramentas de invasao no disco (com hashes) |
| AM-06 | MEDIO | Binario executando fora do caminho padrao |
| AM-07 | MEDIO | Servicos de acesso remoto expostos |
| AM-08 | MEDIO | Arquivos truncados/removidos na imagem |
| AM-09 | MEDIO | Servicos ativos fora da baseline |

Cada achado traz: comando CLI que reproduz a prova, fontes correlacionadas,
lista de evidencias (sem truncamento) e conclusao pericial.
