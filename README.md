# SOC Log Analyzer

Ferramenta de linha de comando (CLI), **100% em Python puro** (sem dependências externas), voltada para fins **educacionais** de análise de logs em contexto de SOC (Security Operations Center).

Ela lê arquivos de log de autenticação (estilo `sshd`/syslog) e de acesso web (estilo Common Log Format), aplica um motor de detecção baseado em **Regex** e gera:

- Um **relatório resumido no terminal**, com incidentes ordenados por severidade;
- Um **relatório estruturado em JSON**, pronto para ser consumido por outras ferramentas (SIEM, dashboards, scripts de automação, etc).

> **Aviso**: este projeto foi criado com fins de estudo/portfólio. Os dados de exemplo (`auth_sample.log`) são fictícios. Não é uma ferramenta de produção nem substitui soluções de SIEM/EDR reais.

---

## Funcionalidades

- **Detecção de Brute Force SSH** identifica múltiplas falhas de login consecutivas do mesmo IP dentro de uma janela de tempo configurável.
- **Detecção de Path Traversal / LFI** — identifica padrões como `../../`, `/etc/passwd`, `/etc/shadow`, etc. em URLs de logs web.
- **Detecção de URLs suspeitas** identifica probes comuns (SQLi, `wp-admin`, `phpmyadmin`, `.env`, `.git`, XSS, etc.).
- **Classificação de severidade** `LOW`, `MEDIUM`, `HIGH`, calculada com base no tipo e volume do incidente.
- **Exportação em JSON** — relatório estruturado, com evidências (linhas de log originais) por incidente.
- **Zero dependências externas** utiliza apenas a biblioteca padrão do Python (`re`, `json`, `argparse`, `datetime`, `pathlib`, etc.).

---

## Estrutura do projeto

```
soc-log-analyzer/
├── soc_log_analyzer.py   # Código-fonte principal da ferramenta
├── auth_sample.log       # Arquivo de log fictício para testes
└── README.md
```

---

## Requisitos

- Python **3.9+** (recomendado 3.10 ou superior)
- Nenhuma dependência externa (apenas bibliotecas padrão)

---

## Como usar

### 1. Clonar o repositório

```bash
git clone https://github.com/joaomouraDDS/soc-log-analyzer.git
cd soc-log-analyzer
```

### 2. (Opcional) Criar um ambiente virtual

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
```

### Dependências

```apt update
sudo apt install python3-reportlab
sudo apt install pyton3-matplotlib
```
ou basta executar o comando:

```pip install -r requirements.txt```

### 3. Executar a análise

```bash
python3 soc_log_analyzer.py --input auth_sample.log --output-pdf incident_report.pdf
```

### 4. Parâmetros disponíveis

| Parâmetro         | Obrigatório | Descrição                                                                 |
|--------------------|:-----------:|-----------------------------------------------------------------------------|
| `-i`, `--input`    | ✅          | Caminho do arquivo de log de entrada.                                       |
| `-o`, `--output`   | ❌          | Caminho do relatório JSON de saída (padrão: `incident_report.json`).        |
| `--year`           | ❌          | Ano a assumir para timestamps de syslog sem ano explícito (padrão: ano atual). |

### Exemplo de saída no terminal

```
======================================================================
 SOC LOG ANALYZER — RELATÓRIO DE ANÁLISE
======================================================================
 Arquivo analisado : auth_sample.log
 Linhas totais     : 35
 Linhas parseadas  : 34
 Incidentes        : 8
   HIGH: 3   MEDIUM: 5   LOW: 0
----------------------------------------------------------------------
[1] (HIGH) SSH_BRUTE_FORCE
     IP de origem : 203.0.113.99
     Descrição    : Detectadas 9 falhas de login SSH consecutivas...
     Ocorrências  : 9
     Período      : 2026-08-30T15:02:10 → 2026-08-30T15:03:14
----------------------------------------------------------------------
...
```

---

## Como funciona a detecção

### Brute Force SSH
O parser identifica linhas `Failed password ... from <IP>` e agrupa as tentativas por IP dentro de uma **janela deslizante de tempo** (padrão: 120 segundos). Se o número de falhas no cluster atingir o limiar configurado (padrão: 4), um incidente é gerado:

- `MEDIUM` — entre o limiar e o dobro do limiar de tentativas;
- `HIGH` — acima do dobro do limiar.

### Path Traversal
URLs contendo padrões como `../`, `%2e%2e%2f`, `/etc/passwd`, `/etc/shadow`, etc. geram incidentes `HIGH`.

### URLs suspeitas
URLs contendo indícios de SQL Injection, XSS, acesso a painéis administrativos (`wp-admin`, `phpmyadmin`), arquivos sensíveis (`.env`, `.git`) etc. geram incidentes `MEDIUM`.

Todas as regras e limiares estão centralizados no topo de `soc_log_analyzer.py`, facilitando ajustes:

```python
BRUTE_FORCE_THRESHOLD = 4
BRUTE_FORCE_WINDOW_SECONDS = 120
PATH_TRAVERSAL_PATTERNS = [...]
SUSPICIOUS_URL_PATTERNS = [...]
```

---

## 🗺️ Roadmap (ideias de evolução)

- [ ] Suporte a mais formatos de log (Nginx, Apache combined, Windows Event Log via `.evtx`).
- [ ] Enriquecimento de IP (geolocalização, reputação) via APIs externas opcionais.
- [ ] Exportação também em CSV/HTML.
- [ ] Modo "watch" para monitorar arquivos de log em tempo real (`tail -f`).
- [ ] Testes automatizados com `pytest`.
- [ ] Empacotamento como pacote instalável via `pip`.

---

## Contribuindo

Sugestões, issues e pull requests são bem-vindos! Este é um projeto de estudo/portfólio, então feedbacks sobre boas práticas de Python e de detecção são especialmente valiosos.

---

## Licença

Distribuído sob a licença MIT. Você é livre para usar, estudar e adaptar.
