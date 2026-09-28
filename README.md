# AnaliseForense

Análise forense automatizada de imagem de **memória** (Volatility 3) e de **disco**
(The Sleuth Kit / pytsk3), com detecção de indícios de ameaça e geração de um
**relatório PDF** que abre com o capítulo **Metodologia** e segue com
**Evidências e Indícios de Ameaça**.

| Você quer... | Faça |
| --- | --- |
| Só testar se tudo instala | [Teste rápido (sem imagens)](#4-teste-rápido-sem-imagens) |
| Rodar a análise de verdade | [Execução completa](#5-execução-completa) |
| Trocar as imagens de entrada | [Onde colocar as evidências](#3-onde-colocar-as-evidências) |
| Resolver um erro | [Problemas comuns](#9-problemas-comuns) |

---

## 1. Requisitos

| Item | Detalhe |
| --- | --- |
| Python | 3.10 ou superior (testado com 3.12.10, Windows) |
| Sistema | Windows, Linux ou macOS |
| Espaço em disco | ≈ 2 GB livres por dump de memória de 2 GB (cache + PDF) |
| RAM livre | 4 GB ou mais (o Volatility carrega o dump na memória) |
| Internet | Só na instalação das dependências; a análise roda offline |
| Conta/Git | Git para clonar o repositório |

As dependências são só três e ficam no `requirements.txt`:
`volatility3==2.28.2`, `pytsk3==20260715`, `reportlab==5.0.1`.

> **Importante:** a pasta `data/` (e as imagens forenses) **não é versionada**.
> Quem clona o repositório começa sem imagens — por isso o projeto roda mesmo
> sem evidências ([teste rápido](#4-teste-rápido-sem-imagens)).

## 2. Início rápido

Copie e cole o bloco do seu sistema.

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
git clone https://github.com/Melinh0/AnaliseForense.git
cd AnaliseForense
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe relatorio_forense.py
```

</details>

<details>
<summary><b>Linux / macOS</b></summary>

```bash
git clone https://github.com/Melinh0/AnaliseForense.git
cd AnaliseForense
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python relatorio_forense.py
```

</details>

Sem imagens em `data/`, o comando acima ainda assim gera um PDF (com aviso de
mídia ausente) — é a forma mais rápida de confirmar que a instalação funcionou.
Para a análise real, coloque as evidências conforme o próximo passo.

## 3. Onde colocar as evidências

Crie a pasta `data/` (se não existir) e deixe os arquivos com estes nomes:

| Arquivo padrão | O que é | Formato aceito |
| --- | --- | --- |
| `data/memory.raw` | Dump da memória volátil | bruto (`raw`, `vmem`, `mem`, `dmp` de aquisição física) |
| `data/disk.dd` | Imagem de disco | bruto (`dd`, `raw`, `img`) |

Nomes ou caminhos diferentes? Use as opções `--memoria` e `--disco`
([tabela de opções](#7-opções-de-linha-de-comando)).

**Como conseguir imagens de teste (não use evidências reais de um caso):**

- **Disco:** `dd if=/dev/sda of=disk.dd bs=4M status=progress` (Linux) ou imagem
  criada em laboratório a partir de uma VM.
- **Memória:** aquisição com ferramenta de captação (ex.: WinPmem, AVML) dentro
  de uma VM de teste.
- Bancos públicos de imagens forenses (ex.: CFReDS do NIST) também servem.

**O que funciona melhor:** o motor de detecção é voltado para **Windows**
(processos, serviços e estruturas do kernel). Imagens de outros sistemas geram
PDF, mas com poucos ou nenhum achado.

## 4. Teste rápido (sem imagens)

Valida a instalação em menos de 1 segundo. O `--saida` separado evita
sobrescrever um laudo já gerado:

**Windows**

```powershell
.\.venv\Scripts\python.exe relatorio_forense.py --memoria inexistente.raw --disco inexistente.dd --saida data\relatorios\teste_instalacao.pdf
```

**Linux / macOS**

```bash
python relatorio_forense.py --memoria inexistente.raw --disco inexistente.dd --saida data/relatorios/teste_instalacao.pdf
```

Saída esperada: avisos `[AVISO] ... não encontrado`, nenhum achado e
`Relatório PDF gerado: ... teste_instalacao.pdf`.
Se apareceu isso, a instalação está OK — siga para a execução completa.

## 5. Execução completa

Com `data/memory.raw` e `data/disk.dd` no lugar, rode o comando do
[início rápido](#2-início-rápido).

**Primeira execução (sem cache):**

1. `Integridade das mídias - hash ANTES...` — MD5/SHA256 das duas mídias
   (para um dump de 2 GB, de segundos a poucos minutos).
2. `Coletando processos... / cmdlines... / rede...` — 14 plugins do Volatility 3.
3. `Lendo layout de partições... / Listando arquivos (recursivo)...` — varredura do disco via TSK.
4. `Executando motor de detecção...` — regras AM-01 a AM-10.
5. `Integridade das mídias - hash DEPOIS...` — comparação antes/depois.
6. `INDÍCIOS DETECTADOS` + `Veredicto:` — resumo na tela.
7. `Relatório PDF gerado: ...` — laudo completo.

**Tempo de referência (máquina de teste, Windows):**

| Cenário | Tempo |
| --- | --- |
| Sem imagens (teste rápido) | ~0,2 s |
| Com cache (reexecução) | ~30 s (quase todo o tempo é o hash das mídias) |
| Primeira vez, dump de 2 GB | alguns minutos (coleta dos 14 plugins) |

**Depois disso a coleta fica em cache** — as próximas execuções são rápidas.
Use `--sem-cache` para reexecutar tudo do zero.

## 6. Saídas

| Arquivo | Conteúdo |
| --- | --- |
| `data/relatorios/relatorio_forense.pdf` | Laudo completo (32 páginas na execução de referência) |
| `data/cache/memoria.pkl` | Cache da coleta de memória |
| `data/cache/disco.pkl` | Cache da coleta de disco |

Tudo dentro de `data/` fica fora do versionamento (`data/` está no
`.gitignore`), então cada execução gera os seus próprios arquivos.

**O que tem dentro do PDF:** capa (com veredito de integridade) → **Cap. 0
Metodologia** (ferramentas e versões, integridade, pipeline de formação da
evidência, critérios de severidade, mecanismo de detecção de cada plugin do
Volatility e de cada API/flag do TSK, cadeia de prova, limitações) → **Cap. 1
Evidências** (resumo executivo, tabela dos 10 achados, detalhamento das provas)
→ Anexos I/II (saída bruta por ferramenta).

## 7. Opções de linha de comando

| Opção | Padrão | Para que serve |
| --- | --- | --- |
| `--memoria <caminho>` | `data/memory.raw` | Caminho do dump de memória |
| `--disco <caminho>` | `data/disk.dd` | Caminho da imagem de disco |
| `--offset <n>` | `0` | Offset do sistema de arquivos na imagem de disco |
| `--saida <caminho>` | `data/relatorios/relatorio_forense.pdf` | Onde salvar o PDF |
| `--sem-cache` | desligado | Ignora `data/cache` e refaz toda a coleta |
| `-h` / `--help` | - | Mostra a ajuda do programa |

Exemplos:

```powershell
.\.venv\Scripts\python.exe relatorio_forense.py --disco D:\casos\disco.dd --offset 1048576
.\.venv\Scripts\python.exe relatorio_forense.py --saida C:\saida\laudo.pdf --sem-cache
```

```bash
python relatorio_forense.py --memoria /evidencias/mem.raw --disco /evidencias/disk.dd
```

## 8. Estrutura do projeto

| Arquivo | Função |
| --- | --- |
| `relatorio_forense.py` | Executável principal (coleta + detecção + PDF) |
| `coletores_memoria.py` | Plugins do Volatility 3 (`pslist`, `cmdline`, `netscan`, `malfind`, `psxview`, `ldrmodules`, `hollowprocesses`, `suspicious_threads`, `svcscan`, `filescan`, `dlllist`, `handles`, `privs`, `envars`) |
| `coletores_disco.py` | pytsk3: partições, arquivos, deletados, hashes MD5/SHA256, IOCs, ferramentas de ataque |
| `deteccao.py` | Motor de regras AM-01..AM-10 com evidências, correlação entre fontes e veredicto |
| `metodologia.py` | Conteúdo do capítulo de metodologia (ferramentas, pipeline, mecanismos Volatility/TSK, limitações) |
| `integridade.py` | Hash MD5/SHA256 das mídias antes e depois da análise (prova de não adulteração) |
| `relatorio_pdf.py` | Montagem do PDF (Cap. 0 de metodologia, Cap. 1 de provas + anexos por ferramenta) |
| `requirements.txt` | Dependências instaladas pelo `pip` |
| `data/` | Imagens forenses e saídas (**não versionada**) |

**Ferramentas do fluxo:** Volatility 3 (memória), The Sleuth Kit — TSK (disco,
integrado ao pipeline pela API `pytsk3`) e Autopsy, que pode ser usado em paralelo
para inspeção manual/apoio da imagem de disco. Todas operam em modo **somente
leitura**: nenhuma mídia é montada em escrita ou executada.

O código não contém comentários internos — a explicação técnica está toda no
capítulo Metodologia do PDF.

## 9. Problemas comuns

| Sintoma | Causa provável | Solução |
| --- | --- | --- |
| `'python' não é reconhecido` | Python fora do PATH | No Windows, use `py -m venv .venv` ou reinstale marcando *Add to PATH* |
| `Could not find a version that satisfies pytsk3` (Linux/macOS) | Sem compilação disponível | `sudo apt install build-essential python3-dev` e rode o `pip install` de novo |
| `[AVISO] Dump de memória não encontrado` | `data/` vazia ou nome diferente | Coloque os arquivos em `data/memory.raw` e `data/disk.dd`, ou use `--memoria` / `--disco` |
| `Pulando coleta de memória` + PDF sem achados | Mídia ausente | É o comportamento esperado sem imagens; adicione as evidências |
| `Coleta com erros em memoria: cache NÃO gravado` | Algum plugin do Volatility falhou | Leia a linha `erro em <plugin>: ...` acima; em geral o dump não é de Windows ou está corrompido |
| Poucos achados em imagem Linux/Outro SO | As regras AM são voltadas para Windows | Use imagens de Windows ou trate o resultado como análise de disco (TSK segue funcionando) |
| Quer forçar uma nova coleta | Cache antigo | `--sem-cache` |
| Quer gerar outro PDF sem sobrescrever o atual | - | `--saida outro_nome.pdf` |
| Acentos bagunçados no console Windows | Codepage do terminal | `chcp 65001` antes de rodar |
| `PermissionError` ao gravar cache/PDF | Pasta protegida | Rode na pasta do repositório ou escolha outro `--saida` |
| Processo lento / memória alta | Dump muito grande | Feche outros programas; o dump é carregado na RAM |

## 10. Como funciona a análise

```
aquisição (somente leitura)
        │
        ▼
coleta ── Volatility 3 (14 plugins)  ──┐
        └─ TSK/pytsk3 (partições,      ├─ data/cache/*.pkl
           arquivos, hashes, IOCs)   ──┘
        │
        ▼
detecção ── regras AM-01..AM-10 (severidade + correlação de fontes)
        │
        ▼
integridade ── MD5/SHA256 antes × depois  →  INALTERADA / ALTERADA
        │
        ▼
PDF ── Cap. 0 Metodologia + Cap. 1 Evidências + Anexos
```

Cada achado traz o comando CLI que reproduz a prova, as fontes que se cruzam,
a lista de evidências completas e a conclusão pericial.

## 11. Integridade das mídias

Para provar que `data/memory.raw` e `data/disk.dd` não foram adulterados,
`integridade.py` calcula MD5 e SHA256 (leitura única, em blocos):

1. **antes** de qualquer plugin do Volatility ou varredura TSK rodar;
2. **depois** que a detecção termina, antes de gerar o PDF.

As duas leituras são comparadas e o resultado (`INALTERADA` / `ALTERADA` /
`NÃO-VERIFICÁVEL`) aparece na capa, na seção 0.2 do laudo e no console.

## 12. Achados (regras AM)

| ID | Sev. | Título |
| --- | --- | --- |
| AM-01 | CRÍTICO | Execução de script suspeito em pasta de risco |
| AM-02 | CRÍTICO | Processos ocultos/ausentes da lista ativa |
| AM-03 | CRÍTICO | Injeção de código em região executável |
| AM-10 | CRÍTICO | Evasão avançada: hollowing, threads suspeitas e DLLs desvinculadas |
| AM-04 | ALTO | Conexões externas ativas (possível C2) |
| AM-05 | ALTO | Ferramentas de invasão no disco (com hashes) |
| AM-06 | MÉDIO | Binário executando fora do caminho padrão |
| AM-07 | MÉDIO | Serviços de acesso remoto expostos |
| AM-08 | MÉDIO | Arquivos truncados/removidos na imagem |
| AM-09 | MÉDIO | Serviços ativos fora da baseline |

Na execução de referência o laudo fecha com **10 achados: 4 CRÍTICO, 2 ALTO,
4 MÉDIO** e o veredicto de que há indícios suficientes de ameaça, com cadeia de
prova formada pela correlação entre processos, linhas de comando, regiões de
memória, conexões de rede e conteúdo em disco.

## 13. Metodologia detalhada no PDF

O **Capítulo 0** do laudo responde como ele é construído:

| Seção | Conteúdo |
| --- | --- |
| 0.1 | Ferramentas utilizadas, versão de cada uma e como foram invocadas |
| 0.2 | Integridade das mídias (hash antes e depois da análise) |
| 0.3 | Pipeline de formação de uma evidência (aquisição → coleta → regra → correlação) |
| 0.4 | Critérios de severidade (CRÍTICO/ALTO/MÉDIO/BAIXO) |
| 0.5 | Mecanismo de detecção de cada plugin do Volatility 3 (estrutura varrida) |
| 0.6 | Mecanismo de detecção de cada API/flag do The Sleuth Kit (metadado lido) |
| 0.7 | Cadeia de prova: quais fontes se cruzam em cada regra |
| 0.8 | Limitações do método e risco de falsos positivos |

## 14. Licença

Distribuído sob a licença presente no arquivo [`LICENSE`](LICENSE).
