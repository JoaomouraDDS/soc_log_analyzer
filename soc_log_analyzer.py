#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC Log Analyzer & PDF Report Generator
Autor: Automatizado para Portfólio de Cibersegurança
Descrição: Ferramenta CLI de SOC para análise de logs via Regex, detecção de incidentes,
           geração de gráficos analíticos e exportação de relatório corporativo em PDF.
"""

import os
import sys
import re
import json
import argparse
from datetime import datetime
from collections import Counter

# Tentar importar bibliotecas de gráficos e PDF
try:
    import matplotlib
    matplotlib.use('Agg') # Backend sem interface gráfica
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ==========================================
# CONFIGURAÇÕES E LIMITES DE DETECÇÃO (SOC)
# ==========================================
BRUTE_FORCE_THRESHOLD = 5  # Número mínimo de falhas para considerar Brute Force
TIME_WINDOW_SECONDS = 300  # Janela de tempo simulada

SUSPICIOUS_URL_PATTERNS = [
    "/wp-admin/", "/setup-config.php", "/.env", "/.git",
    "../", "etc/passwd", "etc/shadow", "eval(", "UNION SELECT"
]


class SOCAnalyzerError(Exception):
    """Exceção customizada para erros no SOC Log Analyzer."""
    pass


class LogParser:
    """Responsável por ler e interpretar linhas de arquivos de log."""
    
    @staticmethod
    def parse_line(line):
        line = line.strip()
        if not line:
            return None
        
        # Regex para formato syslog / access log comum
        syslog_pattern = re.compile(
            r'\[(?P<timestamp>[^\]]+)\]\s+\[(?P<service>[^\]]+)\]\s+IP:\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+(?P<message>.*)'
        )
        match = syslog_pattern.match(line)
        if match:
            return match.groupdict()
        
        # Regex genérica caso o log venha em outro formato
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
        if ip_match:
            return {
                "timestamp": datetime.now().isoformat(),
                "service": "GENERIC_LOG",
                "ip": ip_match.group(0),
                "message": line
            }
        return None


class DetectionEngine:
    """Motor de detecção de ameaças baseado em padrões e heurísticas."""
    
    def __init__(self, log_entries):
        self.log_entries = log_entries
        self.incidents = []

    def run_analysis(self):
        # 1. Análise de Brute Force SSH / Autenticação
        ssh_attempts = {}
        for entry in self.log_entries:
            msg = entry["message"].lower()
            if "failed password" in msg or "invalid user" in msg or "auth failed" in msg:
                ip = entry["ip"]
                if ip not in ssh_attempts:
                    ssh_attempts[ip] = []
                ssh_attempts[ip].append(entry)

        for ip, attempts in ssh_attempts.items():
            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                users_targeted = set()
                for att in attempts:
                    m = re.search(r'(?:user\s+|for\s+)([a-zA-Z0-9_\-]+)', att["message"])
                    if m:
                        users_targeted.add(m.group(1))
                
                severity = "HIGH" if len(attempts) >= 8 else "MEDIUM"
                self.incidents.append({
                    "type": "SSH_BRUTE_FORCE",
                    "severity": severity,
                    "source_ip": ip,
                    "description": f"Detectadas {len(attempts)} falhas de login consecutivas a partir do IP {ip}, visando usuário(s): {', '.join(users_targeted) if users_targeted else 'desconhecido'}.",
                    "count": len(attempts),
                    "first_seen": attempts[0]["timestamp"],
                    "last_seen": attempts[-1]["timestamp"]
                })

        # 2. Análise de Web / Path Traversal / URLs Maliciosas
        for entry in self.log_entries:
            msg = entry["message"]
            for pattern in SUSPICIOUS_URL_PATTERNS:
                if pattern in msg:
                    severity = "HIGH" if ("../" in pattern or "etc/" in pattern or "UNION" in pattern) else "MEDIUM"
                    inc_type = "PATH_TRAVERSAL_ATTEMPT" if "../" in pattern or "etc/" in pattern else "SUSPICIOUS_URL_ACCESS"
                    
                    self.incidents.append({
                        "type": inc_type,
                        "severity": severity,
                        "source_ip": entry["ip"],
                        "description": f"Atividade suspeita detectada a partir do IP {entry['ip']} acessando padrão malicioso: {pattern}",
                        "count": 1,
                        "first_seen": entry["timestamp"],
                        "last_seen": entry["timestamp"]
                    })
                    break

        return self.incidents


class ReportGenerator:
    """Responsável por exportar relatórios em JSON e em PDF profissional com gráficos."""
    
    def __init__(self, incidents, filename, total_lines, parsed_lines):
        self.incidents = incidents
        self.filename = filename
        self.total_lines = total_lines
        self.parsed_lines = parsed_lines

    def save_json(self, output_path):
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "total_lines_analyzed": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "total_incidents": len(self.incidents),
            "incidents": self.incidents
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

    def generate_charts(self, chart_path):
        if not MATPLOTLIB_AVAILABLE:
            return None
        
        severities = [inc["severity"] for inc in self.incidents]
        sev_counts = Counter(severities)
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        
        if sev_counts:
            ax1.bar(sev_counts.keys(), sev_counts.values(), color=['#d9534f' if k=='HIGH' else '#f0ad4e' for k in sev_counts.keys()])
            ax1.set_title("Incidentes por Severidade", fontsize=11, fontweight='bold', color='#333333')
            ax1.set_ylabel("Quantidade", fontsize=9)
            ax1.grid(axis='y', linestyle='--', alpha=0.7)
        
        types = [inc["type"] for inc in self.incidents]
        type_counts = Counter(types)
        if type_counts:
            ax2.barh(list(type_counts.keys()), list(type_counts.values()), color='#0275d8')
            ax2.set_title("Tipos de Ameaça Detectadas", fontsize=11, fontweight='bold', color='#333333')
            ax2.set_xlabel("Ocorrências", fontsize=9)
            ax2.grid(axis='x', linestyle='--', alpha=0.7)
            plt.tight_layout()
            
        plt.savefig(chart_path, dpi=200, bbox_inches='tight')
        plt.close()
        return chart_path

    def save_pdf(self, output_path):
        if not REPORTLAB_AVAILABLE:
            raise SOCAnalyzerError("ReportLab não está instalado.")
        
        chart_file = "soc_chart_temp.png"
        if MATPLOTLIB_AVAILABLE:
            self.generate_charts(chart_file)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, textColor=colors.HexColor('#1a202c'), spaceAfter=4)
        subtitle_style = ParagraphStyle('ReportSubtitle', parent=styles['Normal'], fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#718096'), spaceAfter=15)
        section_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#2d3748'), spaceBefore=10, spaceAfter=6)
        cell_style = ParagraphStyle('CellText', parent=styles['Normal'], fontName='Helvetica', fontSize=8.5, textColor=colors.HexColor('#2d3748'))
        cell_bold = ParagraphStyle('CellTextBold', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8.5, textColor=colors.HexColor('#1a202c'))

        elements = []

        elements.append(Paragraph("SOC SECURITY INCIDENT REPORT", title_style))
        elements.append(Paragraph(f"Arquivo analisado: {self.filename} | Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#cbd5e0'), spaceAfter=12))

        high_count = sum(1 for i in self.incidents if i['severity'] == 'HIGH')
        med_count = sum(1 for i in self.incidents if i['severity'] == 'MEDIUM')
        
        summary_data = [
            [Paragraph("<b>Linhas Totais</b>", cell_bold), Paragraph("<b>Linhas Analisadas</b>", cell_bold), Paragraph("<b>Total Incidentes</b>", cell_bold), Paragraph("<b>Severidade HIGH</b>", cell_bold), Paragraph("<b>Severidade MEDIUM</b>", cell_bold)],
            [Paragraph(str(self.total_lines), cell_style), Paragraph(str(self.parsed_lines), cell_style), Paragraph(str(len(self.incidents)), cell_style), Paragraph(str(high_count), cell_style), Paragraph(str(med_count), cell_style)]
        ]
        
        summary_table = Table(summary_data, colWidths=[100, 110, 100, 100, 130])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#edf2f7')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e0'))
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        if MATPLOTLIB_AVAILABLE and os.path.exists(chart_file):
            elements.append(Paragraph("Análise Gráfica de Ameaças", section_style))
            elements.append(Image(chart_file, width=500, height=200))
            elements.append(Spacer(1, 15))

        elements.append(Paragraph("Detalhes dos Incidentes Detectados", section_style))
        
        table_data = [[
            Paragraph("<b>Sev</b>", cell_bold),
            Paragraph("<b>Tipo de Incidente</b>", cell_bold),
            Paragraph("<b>IP de Origem</b>", cell_bold),
            Paragraph("<b>Descrição / Detalhes</b>", cell_bold)
        ]]

        for inc in self.incidents:
            sev_color = '#d9534f' if inc['severity'] == 'HIGH' else '#f0ad4e'
            sev_p = Paragraph(f"<font color='{sev_color}'><b>{inc['severity']}</b></font>", cell_style)
            type_p = Paragraph(inc['type'], cell_style)
            ip_p = Paragraph(inc['source_ip'], cell_style)
            desc_p = Paragraph(inc['description'], cell_style)
            table_data.append([sev_p, type_p, ip_p, desc_p])

        incident_table = Table(table_data, colWidths=[55, 120, 95, 270])
        incident_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#edf2f7')),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0'))
        ]))
        elements.append(incident_table)

        doc.build(elements)

        if os.path.exists(chart_file):
            os.remove(chart_file)


def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer & PDF Report Generator")
    parser.add_argument("--input", required=True, help="Caminho para o arquivo de log de entrada")
    parser.add_argument("--output-json", default="incident_report.json", help="Caminho para salvar o JSON")
    parser.add_argument("--output-pdf", default="incident_report.pdf", help="Caminho para salvar o relatório em PDF")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERRO] Arquivo não encontrado: {args.input}")
        sys.exit(1)

    print(f"[*] Lendo arquivo de log: {args.input}...")
    total_lines = 0
    parsed_lines = 0
    entries = []

    with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            total_lines += 1
            parsed = LogParser.parse_line(line)
            if parsed:
                parsed_lines += 1
                entries.append(parsed)

    print(f"[*] Executando motor de detecção de ameaças...")
    engine = DetectionEngine(entries)
    incidents = engine.run_analysis()

    print(f"[+] Análise concluída! {len(incidents)} incidentes detectados.")

    reporter = ReportGenerator(incidents, args.input, total_lines, parsed_lines)
    
    reporter.save_json(args.output_json)
    print(f"[+] Relatório JSON salvo em: {args.output_json}")

    try:
        reporter.save_pdf(args.output_pdf)
        print(f"[+] Relatório executivo em PDF com gráficos gerado com sucesso: {args.output_pdf}")
    except Exception as e:
        print(f"[!] Erro ao gerar PDF: {e}")

if __name__ == "__main__":
    main()
