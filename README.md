# 🛡️ Live Traffic Sniffer (SOC Edition)

Ferramenta profissional de monitoramento de tráfego de rede em tempo real desenvolvida em Python. Projetada para ambientes operacionais de segurança (SOC), permitindo a captura de pacotes, identificação de protocolos, detecção de tráfego suspeito em portas críticas e exportação automatizada de relatórios executivos.

---

## 🚀 Funcionalidades Principais

* **Captura em Tempo Real:** Monitora o tráfego diretamente da placa de rede utilizando a biblioteca `Scapy`.
* **Identificação de Protocolos:** Classifica automaticamente pacotes em `TCP`, `UDP`, `ICMP` e outros.
* **Alertas de Portas Sensíveis:** Monitora e sinaliza tráfego direcionado a portas críticas de serviços vulneráveis ou comuns de ataque (`FTP`, `SSH`, `Telnet`, `HTTP`, `HTTPS`, `RDP`).
* **Filtros Otimizados (BPF):** Utiliza filtros de nível de driver para maior eficiência e menor consumo de CPU.
* **Validação Inteligente de Interface:** Verifica a existência da interface de rede selecionada antes de iniciar a execução.
* **Relatório Executivo e Exportação:** Gera um sumário estatístico detalhado ao encerrar a execução (via `Ctrl+C` ou limite de pacotes) com opção de exportação em formato `.json`.

---

## 🛠️ Requisitos e Pré-requisitos

O projeto foi construído primariamente para ambientes **Linux (Kali Linux)**.

* **Python:** Versão 3.x
* **Biblioteca Scapy:** Para manipulação e sniffer de pacotes de rede.
* **Privilégios de Administrador:** Necessário acesso `root` para escutar a interface de rede.

---

## 📦 Instalação

1. Clone o repositório ou baixe os arquivos do projeto:
   ```bash
   git clone https://github.com/seu-usuario/live-traffic-sniffer.git
   cd live-traffic-sniffer
   ```

2. Instale as dependências necessárias (Scapy):
   ```bash
   pip install scapy
   ```

---

## ⚙️ Como Usar

Como a ferramenta interage diretamente com o driver de rede, execute sempre com privilégios de superusuário (`sudo`).

### 1. Modo Padrão (Escuta livre)

Escuta a interface padrão do sistema até que você decida encerrar:

```bash
sudo python3 live_sniffer.py
```

### 2. Especificando uma Interface de Rede

Para monitorar uma interface específica (ex: `eth0` ou `wlan0`):

```bash
sudo python3 live_sniffer.py -i eth0
```

### 3. Definindo um Limite de Pacotes e Exportando Relatório

Para capturar exatamente `50` pacotes e salvar o resultado em um arquivo JSON de auditoria:

```bash
sudo python3 live_sniffer.py -i eth0 -c 50 -o relatorio.json
```

---

## 📋 Argumentos Disponíveis da CLI

| Argumento | Descrição |
|---|---|
| `-i`, `--interface` | Especifica a interface de rede a ser utilizada (ex: `eth0`, `wlan0`). |
| `-o`, `--output` | Salva o log detalhado e as estatísticas em um arquivo `.json` ao encerrar. |
| `-c`, `--count` | Define o número máximo de pacotes a serem capturados antes de encerrar automaticamente. |

---

## 🔍 Exemplo de Relatório Executivo

```
====================================================
🛡️ RELATÓRIO EXECUTIVO - LIVE TRAFFIC SNIFFER
====================================================

Data/Hora do Encerramento : 2026-09-12 12:30:00
Total de Pacotes Analisados : 150
    ◆ Pacotes TCP        : 90
    ◆ Pacotes UDP        : 55
    ◆ Pacotes ICMP       : 5
    ◆ Outros Protocolos  : 0
⚠️  Alertas de Portas Alvo : 2

[+] Relatório exportado com sucesso para: relatorio.json
[+] Encerrando o monitoramento de rede com segurança.
```

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida exclusivamente para fins educacionais, testes de laboratório e auditorias de segurança autorizadas. O uso impróprio em redes sem consentimento prévio é de total responsabilidade do usuário.

---

## 👤 Autor

Desenvolvido por **Joao Moura** (*Cafeecomcheckpoint*).
