# 📊 SOC Log Analyzer & PDF Report Generator

Ferramenta CLI de Centro de Operações de Segurança (SOC) desenvolvida em Python para análise automatizada de logs corporativos ou de arquivos de tráfego de rede, detecção de ameaças por heurística/Regex, geração de gráficos analíticos e exportação de relatórios executivos profissionais em PDF.

---

## 🚀 Funcionalidades Principais

* **Parser Inteligente:** Interpreta logs tradicionais de sistema (*Syslog/Access log*) e também consome nativamente os relatórios em formato `.json` exportados pelo **Live Traffic Sniffer**.
* **Motor de Detecção de Ameaças:**
  * Identifica tentativas de força bruta (SSH Brute Force).
  * Detecta padrões maliciosos em requisições Web (*Path Traversal*, acesso a arquivos sensíveis como `.env` e `/etc/passwd`, injeções).
  * Sinaliza tráfego de rede direcionado a portas sensíveis a partir de arquivos de captura.
* **Análise Gráfica:** Gera gráficos estatísticos automáticos de severidade e tipos de ameaça utilizando `Matplotlib`.
* **Relatório Executivo Corporativo (PDF):** Compila todas as evidências, tabelas e gráficos em um documento PDF formatado profissionalmente utilizando `ReportLab`.
* **Exportação JSON:** Salva um sumário estruturado de incidentes para integração com outras ferramentas ou pipelines de segurança.

---

## 🛠️ Requisitos e Pré-requisitos

* **Python:** Versão 3.x
* **Bibliotecas Externas:**
  * `matplotlib` (para a geração de gráficos)
  * `reportlab` (para a construção do PDF)

---

## 📦 Instalação

1. Clone o repositório ou baixe os arquivos do projeto:
   ```bash
   git clone https://github.com/JoaomouraDDS/soc_log_analyzer.git
   cd soc_log_analyzer
   ```

2. Instale as dependências necessárias:
   ```bash
   pip install matplotlib reportlab
   ```

---

## ⚙️ Como Usar

### 1. Analisando um log tradicional de sistema

```bash
python3 soc_log_analyzer.py --input /var/log/auth.log --output-pdf relatorio_auth.pdf
```

### 2. Integrando com o Live Traffic Sniffer (Modo Ecossistema SOC)

Primeiro, gere o relatório de rede com o sniffer:

```bash
sudo python3 live_sniffer.py -i eth0 -c 100 -o relatorio_rede.json
```

Em seguida, processe esse JSON com o analisador para gerar o relatório executivo em PDF:

```bash
python3 soc_log_analyzer.py --input relatorio_rede.json --output-pdf relatorio_soc_rede.pdf --output-json incidentes_rede.json
```

---

## 📋 Argumentos Disponíveis da CLI

| Argumento | Descrição |
|---|---|
| `--input` | Caminho para o arquivo de log de entrada (texto plano) ou arquivo `.json` do Live Traffic Sniffer. |
| `--output-pdf` | Caminho/nome para salvar o relatório executivo final em formato PDF (Padrão: `incident_report.pdf`). |
| `--output-json` | Caminho/nome para salvar o sumário analítico em JSON (Padrão: `incident_report.json`). |

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida exclusivamente para fins educacionais, blue teaming, resposta a incidentes e auditorias de segurança autorizadas.

---

## 👤 Autor

Desenvolvido por **Joao Moura** (*Cafeecomcheckpoint*).
