import customtkinter as ctk
import requests
import json
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
import webbrowser
import whois
from google import genai
from google.genai import types
from google.genai.errors import APIError
import time
import threading 
import hashlib 
import re 
import os
import sys
from typing import Dict, Any, Optional

# --- CONSTANTES E CONFIGURAÇÃO DE CHAVES DE API ---

# Removidos placeholders de chaves em plaintext, conforme boas práticas de segurança.
# O código agora busca APENAS variáveis de ambiente. Se não configuradas, retorna ''.
VT_API_KEY = os.environ.get('')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
PULSEDIVE_API_KEY = os.environ.get('PULSEDIVE_API_KEY')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
HA_API_KEY = os.environ.get('HA_API_KEY')

# Configurações globais
VERIFY_SSL = True
HA_USER_AGENT = 'AGREGATOR' # User-Agent Específico para HA
MAX_NVD_DETAILS = 5 # Limite de detalhes de CVEs para consulta NVD

# Configurações de Polling
URLSCAN_MAX_RETRIES = 12 
URLSCAN_SLEEP_TIME = 5

# --- FUNÇÕES DE UTILIDADE E API WRAPPER ---
def resource_path(relative_path):
    """
    Obtém o caminho absoluto para um recurso, funcionando para desenvolvimento
    e para o PyInstaller no arquivo temporário.
    """
    try:
        # PyInstaller cria um diretório temporário e armazena o caminho em _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # Caso não esteja rodando como executável (modo de desenvolvimento)
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def _api_request(url: str, method: str = 'GET', headers: Optional[Dict[str, str]] = None, 
                params: Optional[Dict[str, str]] = None, json_data: Optional[Dict[str, Any]] = None, 
                files: Optional[Dict[str, Any]] = None, timeout: int = 15) -> Dict[str, Any]:
    """Função wrapper genérica para requisições HTTP, padronizando o tratamento de erros."""
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params, timeout=timeout, verify=VERIFY_SSL)
        elif method == 'POST':
            response = requests.post(url, headers=headers, params=params, json=json_data, files=files, timeout=timeout, verify=VERIFY_SSL)
        else:
            return {"Status": f"ERRO INTERNO: Método HTTP {method} não suportado."}

        # Tratar Status Codes comuns de erro
        if response.status_code == 401:
            return {"Status": "ERRO (401): Não Autorizado. Verifique a chave de API."}
        if response.status_code == 403:
            return {"Status": "ERRO (403): Acesso Proibido. Permissões insuficientes ou chave inválida."}
        if response.status_code == 404:
            # Retorna um status claro se o recurso não foi encontrado
            return {"Status": "Nenhuma informação encontrada (404 Not Found)."}
        if response.status_code == 429:
            return {"Status": "ERRO (429): Limite de requisições excedido (Rate Limit)."}
        if 500 <= response.status_code < 600:
            return {"Status": f"ERRO (5xx): Erro do Servidor API (Status: {response.status_code})."}
        
        # Resposta OK (200-299)
        if 200 <= response.status_code < 300:
            try:
                # Tenta retornar o JSON, mas pode ser uma resposta vazia (204)
                return response.json()
            except json.JSONDecodeError:
                return {"Status": f"AVISO: Requisição bem-sucedida, mas resposta não é JSON (Status: {response.status_code})."}
        
        # Qualquer outro erro
        try:
            error_data = response.json()
            error_msg = error_data.get('error', error_data.get('message', 'Sem detalhes de erro.'))
        except:
            error_msg = response.text[:100] if response.text else 'Sem resposta detalhada.'
        
        return {"Status": f"ERRO na requisição (Status: {response.status_code}). Detalhe: {error_msg}"}

    except requests.exceptions.Timeout:
        return {"Status": "ERRO de Conexão: Requisição excedeu o tempo limite (Timeout)."}
    except requests.exceptions.ConnectionError:
        return {"Status": "ERRO de Conexão: Falha ao estabelecer conexão (DNS ou Rede)."}
    except requests.exceptions.RequestException as e:
        return {"Status": f"ERRO de Conexão: Um erro inesperado ocorreu. ({e})"}

def is_ip(observable):
    parts = observable.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

def is_hash(observable):
    return observable.isalnum() and len(observable) in [32, 40, 64]

def is_cve_id(observable):
    return re.match(r'^CVE-\d{4}-\d{4,}$', observable, re.IGNORECASE)

def format_whois_data(data):
    if not data:
        return {"Status": "Nenhuma informação de registro (Whois) encontrada."}
    output = {}
    if data.registrar:
        output["Registrador"] = data.registrar if isinstance(data.registrar, str) else ", ".join(data.registrar)
    if data.creation_date:
        output["Data de Criação"] = str(data.creation_date)
    if data.expiration_date:
        output["Data de Expiração"] = str(data.expiration_date)
    if data.name_servers:
        output["Servidores de Nome"] = data.name_servers if isinstance(data.name_servers, str) else ", ".join(data.name_servers)
    if data.country:
        output["País"] = data.country
    if not output:
        output["Status"] = "Dados Whois encontrados, mas campos chave estavam vazios."
    return output

def search_whois(observable):
    if is_hash(observable) or is_cve_id(observable):
        return {"Status": "Não aplicável: Whois suporta apenas IP ou Domínio."}
    try:
        w = whois.whois(observable)
        return format_whois_data(w)
    except Exception as e:
        return {"Status": f"ERRO ao buscar Whois: {e}"}

# --- BUSCA DETALHADA DE CVE NO NVD ---
def search_nvd(cve_id):
    if not is_cve_id(cve_id):
        return {"Status": f"Formato inválido para CVE ID: {cve_id}"}
    url = f"https://services.nvd.nist.gov/rest/json/pub/v1/cves?cveId={cve_id}" 
    
    response = _api_request(url, timeout=10)
    
    if "Status" in response and "ERRO" in response["Status"]:
        return response
    
    # Processa dados NVD
    vulnerabilities = response.get('vulnerabilities', [])
    if not vulnerabilities:
        return {"Status": f"CVE ID {cve_id} não encontrado no NVD ou dados vazios."}
    
    cve_item = vulnerabilities[0].get('cve', {})
    cvss_metrics = cve_item.get('metrics', {}).get('cvssMetricV31', [])
    
    score_v31 = 'N/A'
    vector_v31 = 'N/A'
    if cvss_metrics and cvss_metrics[0].get('cvssData'):
        base_metric = cvss_metrics[0]['cvssData']
        score_v31 = base_metric.get('baseScore', 'N/A')
        vector_v31 = base_metric.get('vectorString', 'N/A')
        
    description_entry = next((desc for desc in cve_item.get('descriptions', []) if desc.get('lang') == 'en'), None)
    description = description_entry.get('value', 'N/A') if description_entry else 'N/A'
    published_date = cve_item.get('published', 'N/A')
    
    return {
        "ID_CVE": cve_id,
        "Descrição (EN)": description,
        "Severidade (CVSS 3.1)": score_v31,
        "Vetor CVSS 3.1": vector_v31,
        "Data de Publicação": published_date.split('T')[0] if published_date != 'N/A' else 'N/A',
        "Link NVD": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    }

# Função search_virustotal
def search_virustotal(observable):
    if not VT_API_KEY:
        return {"Status": "ERRO: Chave de API do VirusTotal não configurada. Verifique a variável de ambiente VT_API_KEY."}
    
    endpoint = ""
    data_type = ""
    if is_hash(observable):
        endpoint = f"files/{observable}"
        data_type = "Hash"
    elif is_ip(observable):
        endpoint = f"ip_addresses/{observable}"
        data_type = "IP"
    elif "." in observable:
        endpoint = f"domains/{observable}"
        data_type = "Domain"
    else:
        return {"Status": "Tipo de dado não reconhecido ou inválido para VT."}
        
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = _api_request(url, headers=headers, timeout=10)
    
    if "Status" in response: # Trata erros 404/429/etc
        return response
        
    data = response.get('data', {}).get('attributes', {})
    last_analysis = data.get('last_analysis_stats', {})
    maliciosos = last_analysis.get('malicious', 0)
    
    tags = ", ".join(data.get('tags', [])) if data.get('tags') else 'N/A'
    threat_label = data.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
    
    first_submission = data.get('first_submission_date', 0)
    last_submission = data.get('last_submission_date', 0)
    
    return {
        "Tipo de Dado": data_type,
        "Motores Maliciosos": f"{maliciosos} de {sum(last_analysis.values())}",
        "Reputação Geral (VT)": data.get('reputation', 'N/A'),
        "Tags de Ameaça": tags, 
        "Família de Ameaça (Sugestão)": threat_label, 
        "Primeira Submissão": str(datetime.fromtimestamp(first_submission)) if first_submission else 'N/A',
        "Última Análise": str(datetime.fromtimestamp(last_submission)) if last_submission else 'N/A' 
    }

# Função search_shodan
def search_shodan(observable):
    if not SHODAN_API_KEY:
        return {"Status": "ERRO: Chave de API do Shodan não configurada. Verifique a variável de ambiente SHODAN_API_KEY."}
    if not is_ip(observable):
        return {"Status": "Não aplicável: Shodan suporta apenas Endereços IP."}
        
    url = f"https://api.shodan.io/shodan/host/{observable}"
    params = {'key': SHODAN_API_KEY}
    
    response = _api_request(url, params=params, timeout=10)

    if "Status" in response:
        # Se 404, retorna o status padrão. Se 403, adiciona um aviso específico.
        if "403" in response["Status"]:
            response["Status"] += " A chave Shodan Community pode não ter permissão para dados detalhados (ex: CVEs)."
        return response
    
    data = response # Shodan API retorna o JSON diretamente
    
    ports = ", ".join(map(str, data.get('ports', []))) if data.get('ports') else 'N/A'
    
    return {
        "Organização (AS)": data.get('org', 'N/A'),
        "Sistema Operacional": data.get('os', 'N/A'),
        "País": data.get('country_name', 'N/A'),
        "Portas Abertas (Shodan)": ports,
    }

# Função search_internetdb (AGORA COM DETALHES DE MÚLTIPLAS CVEs)
def search_internetdb(observable):
    if not is_ip(observable):
        return {"Status": "Não aplicável: InternetDB suporta apenas Endereços IP."}
        
    url = f"https://internetdb.shodan.io/{observable}"
    
    response = _api_request(url, timeout=10)
    
    if "Status" in response:
        return response
        
    data = response
    
    # Lista de CVEs encontrada
    raw_vulns_list = data.get('vulns', [])
    cpe_list = data.get('cpes', [])
    detailed_cve_results = [] # Lista para armazenar detalhes de CVEs
    
    # 1. Ordena a lista de CVEs pelo ano (mais recente primeiro)
    valid_cves = [cve for cve in raw_vulns_list if is_cve_id(cve)]
    sorted_vulns = sorted(
        valid_cves, 
        key=lambda cve: (cve.split('-')[1], cve.split('-')[2]), # Ordena por ano e depois por número sequencial
        reverse=True
    )
    
    # 2. Limita a lista e busca detalhes NVD
    cves_to_detail = sorted_vulns[:MAX_NVD_DETAILS] 

    for cve_id in cves_to_detail:
        cve_detail = search_nvd(cve_id)
        if 'Status' not in cve_detail or 'ERRO' not in cve_detail['Status']:
            detailed_cve_results.append(cve_detail)
        else:
            # Adiciona o CVE com o status de erro, caso a busca no NVD falhe
            detailed_cve_results.append({"ID_CVE": cve_id, "Status": f"Falha ao buscar detalhes NVD: {cve_detail['Status']}"})

    # 3. Monta o resultado final
    results = {
        "Portas Abertas (InternetDB)": ", ".join(map(str, data.get('ports', []))) or 'N/A',
        "Hostnames": ", ".join(data.get('hostnames', [])) or 'N/A',
        "CPEs (Softwares Identificados)": ", ".join(cpe_list) or 'N/A',
        "Total de CVEs Encontradas": len(raw_vulns_list), 
        "CVEs Mais Recentes Detalhadas (NVD)": detailed_cve_results, # Lista de N resultados detalhados
        "raw_vulns_list_total": raw_vulns_list, # Mantém a lista completa, se necessário
    }
    return results

# Função search_abuseipdb
def search_abuseipdb(observable):
    if not ABUSEIPDB_API_KEY:
        return {"Status": "ERRO: Chave de API do AbuseIPDB não configurada. Verifique a variável de ambiente ABUSEIPDB_API_KEY."}
    if not is_ip(observable):
        return {"Status": "Não aplicável: AbuseIPDB suporta apenas Endereços IP."}
        
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    params = {'ipAddress': observable, 'maxAgeInDays': '90', 'verbose': 'True'}
    
    response = _api_request(url, headers=headers, params=params, timeout=10)
    
    if "Status" in response:
        return response
        
    data = response.get('data', {})
    
    reports_list = data.get('reports', [])
    last_comment = reports_list[0].get('comment', 'N/A') if reports_list else 'N/A'
    
    return {
        "Score de Confiança de Abuso": f"{data.get('abuseConfidenceScore', 0)}%",
        "Tipo de Uso do IP": data.get('usageType', 'N/A'), 
        "Total de Reports": data.get('totalReports', 0),
        "Reports de Usuários Distintos": data.get('numDistinctUsers', 0), 
        "País": data.get('countryCode', 'N/A'),
        "Último Reporte": data.get('lastReportedAt', 'N/A'), 
        "Comentário do Último Reporte": last_comment, 
        "Domínio Associado": data.get('domain', 'N/A')
    }

# Função search_pulsedive
def search_pulsedive(observable):
    if not PULSEDIVE_API_KEY:
        return {"Status": "ERRO: Chave de API do Pulsedive não configurada. Verifique a variável de ambiente PULSEDIVE_API_KEY."}
        
    url = 'https://pulsedive.com/api/info.php'
    params = {'indicator': observable, 'key': PULSEDIVE_API_KEY, 'pretty': 1}
    
    response = _api_request(url, params=params, timeout=10)
    
    if "Status" in response:
        # Pulsedive retorna erro como JSON com chave 'error' mesmo com status 200
        if response.get('error'):
            return {"Status": f"ERRO Pulsedive: {response['error']}"}
        return response
        
    data = response
    threat_names = ", ".join([t.get('name', '') for t in data.get('threats', [])]) if data.get('threats') else 'N/A'
    
    return {
        "Risco Geral": data.get('risk', 'N/A'),
        "Tipo de Indicador": data.get('type', 'N/A'),
        "Status (Ativo/Inativo)": data.get('status', 'N/A'),
        "Confiança da Análise": data.get('confidence', 'N/A'),
        "Grupo de Ameaça Associado": threat_names, 
        "Descrição de Risco": data.get('risk_desc', 'N/A'),
        "Última Varredura": data.get('last_scan', 'N/A') 
    }

# Função search_greynoise
def search_greynoise(observable):
    if not is_ip(observable):
        return {"Status": "Não aplicável: GreyNoise Community suporta apenas Endereços IP."}
        
    url = f"https://api.greynoise.io/v3/community/{observable}"
    headers = {"Accept": "application/json"}
    
    response = _api_request(url, headers=headers, timeout=10)
    
    if "Status" in response:
        return response
        
    data = response
    tags = ", ".join(data.get('tags', [])) if data.get('tags') else 'N/A'
    
    if data.get('noise'):
        return {
            "Classificação Geral": data.get('classification', 'N/A'),
            "É Ruído (Noise)": "Sim",
            "Última Vez Visto": data.get('last_seen', 'N/A'), 
            "Nome da Organização": data.get('metadata', {}).get('organization', 'N/A'),
            "Intenção/Tags de Atividade": tags 
        }
    elif data.get('riot'):
        return {
            "Classificação Geral": "Benigno (RIOT)",
            "É Ruído (Noise)": "Não (Benigno)",
            "Detalhes": "O IP faz parte do conjunto RIOT (Trusted/Conhecido).",
            "Organização": data.get('name', 'N/A')
        }
    elif data.get('message') == 'Success' and not data.get('noise'):
        return {
            "Classificação Geral": "Desconhecido",
            "É Ruído (Noise)": "Não",
            "Organização (Metadata)": data.get('metadata', {}).get('organization', 'N/A'),
            "Detalhes": "O IP não é ruído de fundo e não foi visto recentemente por scanners GreyNoise."
        }
    else:
        return {"Status": "Nenhuma informação detalhada encontrada no GreyNoise."}

# Função search_urlscan
def search_urlscan(observable, update_callback=None):
    if not URLSCAN_API_KEY:
        return {"Status": "ERRO: Chave de API do URLScan.io não configurada. Verifique a variável de ambiente URLSCAN_API_KEY."}
    if is_hash(observable):
        return {"Status": "Não aplicável: URLScan.io suporta apenas URL/Domínio/IP."}
        
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    payload = {'url': observable, 'visibility': 'unlisted'} 
    
    # 1. Submissão
    submission_response = _api_request(submit_url, method='POST', headers=headers, json_data=payload, timeout=10)
    
    if "Status" in submission_response:
        return {"Status": f"ERRO ao submeter análise: {submission_response['Status']}"}
        
    submission_data = submission_response
    uuid = submission_data.get('uuid')
    result_web_link = submission_data.get('result')
    
    if not uuid:
        return {"Status": "Análise submetida, mas ID de relatório não retornado."}
        
    result_url = f'https://urlscan.io/api/v1/result/{uuid}/'
    
    # 2. Polling
    for attempt in range(1, URLSCAN_MAX_RETRIES + 1):
        if update_callback:
            update_callback(f"Análise URLScan em andamento. Tentativa {attempt}/{URLSCAN_MAX_RETRIES}. (Aguardando {URLSCAN_SLEEP_TIME}s)")
        time.sleep(URLSCAN_SLEEP_TIME) 
        
        result_response = _api_request(result_url, headers=headers, timeout=10)
        
        if result_response.get('message') == 'Not Found': 
            continue # Continua esperando se o relatório ainda não estiver pronto
            
        if "Status" in result_response and "ERRO" in result_response["Status"]:
            return {"Status": f"ERRO ao buscar resultado: {result_response['Status']}"}
        
        if isinstance(result_response, dict):
            # Resultados Finais
            result_data = result_response
            verdicts = result_data.get('verdicts', {})
            page_data = result_data.get('page', {})
            lists_data = result_data.get('lists', {})
            stats_data = result_data.get('stats', {})
            
            overall_score = verdicts.get('overall', {}).get('score', 0)
            risk_label = "Malicioso" if overall_score >= 70 else ("Suspeito" if overall_score >= 40 else "Limpo")
            top_domains = lists_data.get('domains', [])[:3]
            
            return {
                "Veredito de Risco (Geral)": risk_label,
                "Score (0-100)": overall_score,
                "IP Resolvido (Final)": page_data.get('ip', 'N/A'), 
                "Status HTTP (Final)": page_data.get('status', 'N/A'), 
                "País do Host": page_data.get('country', 'N/A'), 
                "Total de Requisições": stats_data.get('requests', 0), 
                "Domínios de Terceiros Contatados (Top 3)": ", ".join(top_domains) if top_domains else 'N/A', 
                "Relatório Completo (Web)": result_web_link
            }

    return {"Status": f"Análise de URLScan excedeu o tempo limite. Verifique o link web: {result_web_link}"}
    
# --- FUNÇÕES HYBRID ANALYSIS (ARQUIVO) ---

# --- FUNÇÕES HYBRID ANALYSIS (ARQUIVO) ---

def _get_ha_report(sha256, ha_headers):
    """Busca o relatório final, focando no link público robusto."""
    
    robust_link = f"https://hybrid-analysis.com/sample/{sha256}"
    
    # 1. Tenta buscar o resumo do relatório (endpoint pago/premium)
    report_url = f"https://hybrid-analysis.com/api/v2/overview/{sha256}/summary"
    summary_response = _api_request(report_url, headers=ha_headers, timeout=20)

    # 2. Verifica se a API restringiu o acesso (Status 404 ou 403)
    if "Status" in summary_response and any(s in summary_response["Status"] for s in ["404", "403", "Acesso Proibido"]):
        # Se for um erro de acesso limitado, retorna o link como sucesso de busca
        return {
            "Status": "Relatório Completo (Acesso Web Requerido).",
            "SHA256": sha256,
            "Link do Relatório": robust_link, 
            "Veredito HA (API)": "N/A (Acesso Restrito)", # Agora ele mostra que o problema é a API
            "AVISO": "Os detalhes 'Malicious' estão no link acima (API Community limitada).",
        }
        
    # 3. Trata outros erros de API
    if "Status" in summary_response:
        return {
            "Status": f"ERRO ao obter detalhes do relatório: {summary_response['Status']}.",
            "SHA256": sha256,
            "Link do Relatório": robust_link,
        }

    # 4. Se a resposta foi 200 (Sucesso) e contém dados (raro na Community)
    report = summary_response
    verdict = report.get("verdict", "N/A")
    
    return {
        "Veredito HA": verdict,
        "SHA256": sha256,
        "Link do Relatório": robust_link,
        "Ambiente de Análise": report.get('environment_description', 'N/A'),
        "Tipo de Arquivo": report.get('file_type', 'N/A'),
        "AVISO": "Análise completa pode levar minutos para estar disponível.",
    }

# ESTA É A FUNÇÃO CORRIGIDA
def search_hybrid_analysis(file_path, update_callback=None):
    if not os.path.isfile(file_path):
        return {"Status": f"ERRO: Arquivo não encontrado em {file_path}"}
    if not HA_API_KEY:
        return {"Status": "ERRO: Chave de API do Hybrid Analysis não configurada. Verifique a variável de ambiente HA_API_KEY."}
    
    def log(msg):
        if update_callback:
            update_callback(msg)
    
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            file_name = os.path.basename(file_path)
    except Exception as e:
        return {"Status": f"ERRO ao processar arquivo: {e}"}
        
    ha_headers = {
        "api-key": HA_API_KEY,
        "User-Agent": HA_USER_AGENT,
        "accept": "application/json",
    }
    
    lookup_url = f"https://hybrid-analysis.com/api/v2/search/hash"
    submit_url = "https://hybrid-analysis.com/api/v2/submit/file"
    robust_link_on_submit = f"https://hybrid-analysis.com/sample/{sha256}"
    
    # 1. Tenta encontrar um relatório existente
    log(f"🔍 Buscando hash {sha256}...")
    lookup_response = _api_request(lookup_url, headers=ha_headers, params={'hash': sha256}, timeout=15)
    
    if "Status" not in lookup_response or "404" not in lookup_response["Status"]:
        data = lookup_response.get("result", [])
        if data and data[0].get("sha256") == sha256:
            log(f"📥 Relatório existente encontrado. Tentando obter detalhes...")
            return _get_ha_report(sha256, ha_headers)
    
    # 2. Submissão do arquivo (se não foi encontrado ou falha de lookup)
    log(f"📤 Hash não encontrado. Submetendo arquivo '{file_name}' para análise...")
    
    # Prepara o 'data' para ser enviado como parte do multipart/form-data
    # A API espera que isso seja um JSON que é passado como campo 'data' (string)
    # Aqui, requests.post irá serializar e empacotar isso corretamente.
    submission_data = {
        "environment_id": "100", # ID 100 é o Win 7 64-bit default
        # Adicione outros parâmetros se necessário, como 'allow_community_access'
    }
    
    files_data = {"file": (file_name, file_bytes)}
    
    # O método 'requests.post' do Python envia 'data' e 'files' como 'multipart/form-data'.
    # O Hybrid Analysis espera o JSON de configuração no campo 'data'.
    # O wrapper _api_request deve ser ajustado para aceitar um 'data' de formulário ou usar requests.post diretamente.
    
    # AJUSTE NO WRAPPER NECESSÁRIO AQUI:
    # A sua função _api_request aceita 'json_data' e 'files' mas não 'data' (form/text).
    # Vamos reescrever esta seção para usar requests.post diretamente, contornando a limitação do wrapper para este caso POST específico de multipart/form-data que requer 'data' (string) E 'files'.
    
    try:
        log("Utilizando requests.post para multipart/form-data...")
        # A chave 'data' aqui não é o json_data do wrapper, mas sim a data do formulário.
        # Hybrid Analysis exige que os parâmetros de submissão (environment_id) sejam JSON stringificado
        # e passado como um campo 'data' na requisição multipart/form-data.
        
        # NOTE: Sua função _api_request não suporta a estrutura de dados necessária para este POST específico.
        # Modificamos a chamada abaixo para usar requests.post diretamente, mas **o mais correto
        # seria atualizar _api_request para lidar com o parâmetro `data` do requests.post**.
        # Se você deseja manter a consistência do wrapper, a **alternativa** é garantir que `_api_request`
        # envie `json_data` *somente* se `files` for `None`, e enviar `data` e `files` se ambos existirem.
        
        # *** Implementação Direta do Requests (SOLUÇÃO MAIS RÁPIDA) ***
        # Removemos o content-type para o requests tratar automaticamente o multipart/form-data
        temp_headers = {k: v for k, v in ha_headers.items() if k.lower() != 'accept'}
        
        # Convertemos o JSON de configuração para string, conforme esperado pela API do HA no campo 'data'
        submission_json_string = json.dumps(submission_data)
        
        # O campo 'data' no requests.post aceita um dicionário de strings para dados do formulário
        response_post = requests.post(
            submit_url,
            headers=temp_headers, # Aqui só temos api-key e User-Agent
            data={"json": submission_json_string}, # O campo de dados JSON deve ser chamado 'json' ou 'data' no HA
            files=files_data,
            timeout=60,
            verify=VERIFY_SSL,
        )
        
        # Tratamento de erro similar ao _api_request para o POST direto
        if 200 <= response_post.status_code < 300:
            submission = response_post.json()
        elif response_post.status_code == 400:
             # O erro 400 agora deve ser tratado corretamente. Retornamos o link, pois ele é útil.
             try:
                 error_data = response_post.json()
                 error_msg = error_data.get('message', 'Erro 400: Bad Request (Submissão).')
             except:
                 error_msg = response_post.text[:100]
                 
             # Retornamos o link, mesmo com erro 400, pois é o que o usuário deseja
             log(f"AVISO: Submissão retornou ERRO 400. Detalhe: {error_msg}. Link é válido.")
             return {
                "Status": f"AVISO (400): Submissão falhou (Bad Request). Link do Relatório foi extraído.",
                "SHA256": sha256,
                "Link do Relatório": robust_link_on_submit,
                "Detalhe do Erro HA": error_msg,
                "Aviso": "O link acima é o mais robusto, verifique se a submissão está em fila.",
            }
        else:
             return {
                "Status": f"ERRO na submissão (Status: {response_post.status_code}). Detalhe: {response_post.text[:100]}",
                "SHA256": sha256,
                "Link do Relatório": robust_link_on_submit,
            }

    except Exception as e:
        return {
            "Status": f"ERRO de Conexão/JSON na Submissão: {e}",
            "SHA256": sha256,
            "Link do Relatório": robust_link_on_submit,
        }
    
    # Se a submissão foi bem-sucedida (Status 200-299)
    submission_id = submission.get("submission_id")
    
    log(f" Arquivo submetido. Análise em andamento. ID: {submission_id}")
    
    return {
        "Status": "Sucesso na Submissão. Análise em andamento.",
        "SHA256": sha256,
        "Link do Relatório": robust_link_on_submit,
        "ID de Acompanhamento (Curto)": submission_id,
        "Aviso": "O link acima é o mais robusto. O relatório final estará ativo em breve.",
    }

# Função generate_ai_analysis
def generate_ai_analysis(observable, results):
    if not GEMINI_API_KEY:
        return {"Status": "ERRO: Chave de API do Gemini não configurada para análise de IA. Verifique a variável de ambiente GEMINI_API_KEY."}
    if not results:
        return {"Status": "ERRO: Não há resultados de OSINT para analisar."}
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        results_json = json.dumps(results, indent=2, ensure_ascii=False)
        
        # O prompt foi atualizado para considerar a nova estrutura de CVEs
        prompt = f"""
Você é um analista de segurança cibernética sênior e conciso. Sua tarefa é analisar e contextualizar os dados de OSINT fornecidos para o indicador '{observable}'.
        
Sua análise deve ser estruturada e incluir:
1. **Resumo Executivo (Verde/Amarelo/Vermelho):** Determine o nível de risco geral (ex: 'RISCO ALTO - Confiança: 95%', 'RISCO MÉDIO', 'RISCO BAIXO/BENIGNO') com base nas descobertas (Score de Abuso, Motores Maliciosos, Veredito URLScan.io) e justifique brevemente.
2. **Detalhes das Ameaças:** Destaque:
    * Scores de abuso (>50%).
    * Detecções maliciosas (VirusTotal) e, se aplicável, Família de Ameaça/Tags.
    * Classificação de ruído (GreyNoise) ou Intenção de Ataque (Tags).
    * Status HTTP (URLScan) e quaisquer domínios de terceiros contatados.
    * **Análise de Vulnerabilidade (Foco InternetDB):** **Se a seção 'InternetDB/CVE' contiver a sub-chave 'CVEs Mais Recentes Detalhadas (NVD)' com resultados válidos, analise e descreva o risco da vulnerabilidade mais crítica (normalmente a mais recente e com maior CVSS). Mencione o total de CVEs (listado em 'Total de CVEs Encontradas') e explique que a análise se concentra nas {MAX_NVD_DETAILS} mais recentes, mas não despreza o volume total.**
3. **Contexto da Infraestrutura:** Mencione a organização (Shodan/AbuseIPDB), país/cidade e dados de registro (Whois) para contextualização.
4. **Recomendações Acionáveis:** Forneça passos acionáveis (ex: bloquear IP, **mitigar CVEs listadas**, investigar logs de CVE, notificar equipe, etc.).
        
Use linguagem técnica e profissional. Responda apenas com a análise solicitada, sem introduções ou frases de conclusão extras.
        
Dados Brutos de OSINT (JSON):
{results_json}
"""
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.4,
                max_output_tokens=3000
            )
        )
        return response.text
    except APIError as e:
        return f"ERRO na API do Gemini: Verifique sua chave ou limite de uso. Detalhe: {e}"
    except Exception as e:
        return {"Status": f"ERRO inesperado na análise de IA: {e}"}

# --- FUNÇÃO PARA GERAR OS LINKS ---
def generate_osint_links(observable):
    links = {
        "VirusTotal": f"https://www.virustotal.com/gui/search/{observable}",
        "GreyNoise": f"https://viz.greynoise.io/indicator/{observable}",
        "URLScan": f"https://urlscan.io/search/#{requests.utils.quote(observable)}",
        "Shodan": f"https://www.shodan.io/host/{observable}" if is_ip(observable) else None,
        "AbuseIPDB": f"https://www.abuseipdb.com/check/{observable}" if is_ip(observable) else None,
        "Pulsedive": f"https://pulsedive.com/indicator/?ioc={observable}",
        "Whois": f"https://www.whois.com/whois/{observable}",
        "InternetDB": f"https://internetdb.shodan.io/{observable}" if is_ip(observable) else None 
    }
    return links

# --- CLASSE DA INTERFACE GRÁFICA (CustomTkinter) ---



class OSINTApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.current_observable = ""
        self.current_results = {}
        self.current_links = {}
        self.current_ai_report = "" 
        self.title("Agregador OSINT Avançado - IMR TISAFE")
        self.geometry("1050x600")
        self.resizable(False, False)
        try:
            # 1. Obter o caminho absoluto, seja no PyInstaller ou em desenvolvimento
            icon_path = resource_path("icone2.ico")
            
            # 2. Configurar o ícone da janela/aplicativo
            # No Windows, o self.iconbitmap() é a maneira correta.
            # O PyInstaller garante que 'icone2.ico' está acessível via 'resource_path'
            self.iconbitmap(icon_path)
            
        except tk.TclError as e:
            # Se houver erro, a falha é capturada, mas a execução continua.
            print(f"Aviso: Não foi possível carregar o ícone. Erro: {e}")
        except Exception as e:
            print(f"Erro inesperado ao configurar o ícone: {e}")
            
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("green")
        self.grid_columnconfigure(0, weight=0)
        self.grid_rowconfigure(3, weight=0)
        

    
                
                

        # 1. Cabeçalho
        self.header_label = ctk.CTkLabel(self, text="🔒 IMR - TISAFE", font=ctk.CTkFont(family="Arial", size=28, weight="bold"), text_color="#FBC02D")
        self.header_label.grid(row=0, column=0, pady=(10, 10))

        # 2. Frame de Entrada
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.input_frame.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self.input_frame, text="Dado para Análise:", font=("Arial", 14)).grid(row=0, column=0, padx=15, pady=10, sticky="w")
        self.observable_entry = ctk.CTkEntry(self.input_frame, width=300, font=("Arial", 14))
        self.observable_entry.grid(row=0, column=1, padx=(5, 5), pady=10, sticky="ew")
        
        # Botões de Ação
        self.search_button = ctk.CTkButton(self.input_frame, text="Buscar", command=self.start_search_thread, font=("Arial", 14), width=90)
        self.search_button.grid(row=0, column=2, padx=(5, 5), pady=10)
        self.analyze_file_button = ctk.CTkButton(self.input_frame, text="Analisar Arquivo", command=self.open_file_dialog, font=("Arial", 14), width=120, fg_color="#21303B", hover_color="#F9A825") # Cor alterada para destaque
        self.analyze_file_button.grid(row=0, column=3, padx=(5, 5), pady=10)
        self.clear_button = ctk.CTkButton(self.input_frame, text="Limpar", command=self.clear_fields, font=("Arial", 14), fg_color="#21303B", hover_color="#F9A825", width=90)
        self.clear_button.grid(row=0, column=4, padx=(5, 5), pady=10)
        self.save_json_button = ctk.CTkButton(self.input_frame, text="Salvar JSON", command=self.save_results_as_json, font=("Arial", 14), fg_color="#21303B", hover_color="#F9A825", width=90, state="disabled")
        self.save_json_button.grid(row=0, column=5, padx=(5, 5), pady=10)
        self.analyze_ia_button = ctk.CTkButton(self.input_frame, text="Analisar c/ IA", command=self.run_ai_analysis, font=("Arial", 14), fg_color="#21303B", hover_color="#F9A825", width=120, state="disabled")
        self.analyze_ia_button.grid(row=0, column=6, padx=(5, 5), pady=10)
        self.save_ai_report_button = ctk.CTkButton(self.input_frame, text="Salvar Relatório IA", command=self.save_ai_report, font=("Arial", 14), fg_color="#21303B", hover_color="#F9A825", width=120, state="disabled")
        self.save_ai_report_button.grid(row=0, column=7, padx=(5, 15), pady=10)

        # 3. Frame para Links 
        self.link_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.link_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        self.link_frame.grid_columnconfigure((0, 1, 2, 3,4,5,6, 7, 8, 9), weight=1) # Aumenta colunas para links
        
        # 4. Widget de Abas (Tabview)
        self.tabview = ctk.CTkTabview(self, width=1000, height=1000)
        self.tabview.grid(row=3, column=0, padx=20, pady=(20, 10), sticky="n")
        self.tabview.grid_propagate(False)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=1) 
        self.grid_columnconfigure(0, weight=1)
        self.tabview.place(relx=0.5, rely=0.62, anchor="center")
        self.tabview.configure(height=420)
        self.tabview.grid_propagate(False)

        self.tabview.add("Geral")
        self.tabview.add("VirusTotal")
        self.tabview.add("GreyNoise")
        self.tabview.add("URLScan.io") 
        self.tabview.add("Shodan")
        self.tabview.add("InternetDB/CVE")
        self.tabview.add("AbuseIPDB")
        self.tabview.add("Pulsedive")
        self.tabview.add("Whois")
        self.tabview.add("HybridAnalysis") 
        self.tabview.add("Análise IA")
        
        # Fonte alterada para Consolas/monoespaçada para melhor legibilidade de dados de TI
        self.output_map = {
            "Geral": self._create_output_textbox(self.tabview.tab("Geral")),
            "VirusTotal": self._create_output_textbox(self.tabview.tab("VirusTotal")),
            "GreyNoise": self._create_output_textbox(self.tabview.tab("GreyNoise")),
            "URLScan.io": self._create_output_textbox(self.tabview.tab("URLScan.io")),
            "Shodan": self._create_output_textbox(self.tabview.tab("Shodan")),
            "InternetDB/CVE": self._create_output_textbox(self.tabview.tab("InternetDB/CVE")), 
            "AbuseIPDB": self._create_output_textbox(self.tabview.tab("AbuseIPDB")),
            "Pulsedive": self._create_output_textbox(self.tabview.tab("Pulsedive")),
            "Whois": self._create_output_textbox(self.tabview.tab("Whois")),
            "HybridAnalysis": self._create_output_textbox(self.tabview.tab("HybridAnalysis")), 
            "Análise IA": self._create_output_textbox(self.tabview.tab("Análise IA")),
        }
        
    
    def _create_output_textbox(self, parent_tab):
        parent_tab.grid_columnconfigure(0, weight=1)
        parent_tab.grid_rowconfigure(0, weight=1)
        # Alterado para fonte monoespaçada para melhor visualização de dados brutos/organizados
        textbox = tk.Text(parent_tab, wrap="word", font=("Consolas", 11),
                            bg="#1E1E1E", fg="#A8D8A8", padx=10, pady=10, state="disabled")
        textbox.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        return textbox

    def open_link(self, url):
        webbrowser.open_new_tab(url)

    def display_links(self):
        for widget in self.link_frame.winfo_children():
            widget.destroy()
        links = self.current_links
        column = 0
        ctk.CTkLabel(self.link_frame, text="Links Rápidos:", font=("Arial", 14, "bold"), text_color="gray").grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        column += 1
        for name, url in links.items():
            if url:
                link_label = ctk.CTkLabel(self.link_frame, text=f"🌐 {name}", text_color="lightblue", cursor="hand2", font=("Arial", 12, "underline"))
                link_label.bind("<Button-1>", lambda e, u=url: self.open_link(u))
                link_label.grid(row=0, column=column, padx=(10, 0), pady=5, sticky="w")
                column += 1

    def clear_fields(self):
        self.observable_entry.delete(0, "end")
        self.save_json_button.configure(state="disabled")
        self.analyze_ia_button.configure(state="disabled")
        self.save_ai_report_button.configure(state="disabled")
        self.search_button.configure(state="normal", text="Buscar") 
        self.analyze_file_button.configure(state="normal", text="Analisar Arquivo") 
        self.current_results = {}
        self.current_observable = ""
        self.current_links = {}
        self.current_ai_report = ""
        for textbox in self.output_map.values():
            textbox.config(state="normal")
            textbox.delete(1.0, "end")
            textbox.config(state="disabled")
        for widget in self.link_frame.winfo_children():
            widget.destroy()

    def append_output(self, textbox, text):
        textbox.after(0, lambda: self._safe_append_output(textbox, text))

    def _safe_append_output(self, textbox, text):
        """Função interna para inserção segura na caixa de texto."""
        textbox.config(state="normal")
        textbox.insert("end", text)
        textbox.config(state="disabled")
        textbox.see("end")
        
    def _safe_replace_output(self, textbox, text):
        """Função interna para substituir o conteúdo da caixa de texto."""
        textbox.config(state="normal")
        textbox.delete(1.0, "end")
        textbox.insert(1.0, text)
        textbox.config(state="disabled")
        textbox.see("end")

    def start_search_thread(self):
        observable = self.observable_entry.get().strip()
        if not observable:
            self.append_output(self.output_map["Geral"], "⚠️ Por favor, insira um IP, HASH ou DOMÍNIO para começar.")
            return
        self.clear_fields()
        self.current_observable = observable
        self.observable_entry.insert(0, observable) # Mantém o dado na entrada
        self.search_button.configure(state="disabled", text="Buscando...")
        self.analyze_file_button.configure(state="disabled") 
        thread = threading.Thread(target=self.run_search, args=(observable,))
        thread.start()

    def urlscan_update_callback(self, message):
        """Atualiza a caixa de texto do URLScan.io e Geral com o status do polling."""
        self.after(0, lambda: self._update_urlscan_status(message))

    def _update_urlscan_status(self, message):
        """Atualiza a caixa de texto de status de forma segura."""
        textbox_urlscan = self.output_map["URLScan.io"]
        textbox_geral = self.output_map["Geral"]
        
        # Atualiza aba URLScan
        textbox_urlscan.config(state="normal")
        textbox_urlscan.delete(1.0, "end")
        textbox_urlscan.insert(1.0, f"--- URLSCAN.IO ---\n\n{message}")
        textbox_urlscan.config(state="disabled")
        
        # Atualiza a última linha da aba Geral
        textbox_geral.config(state="normal")
        try:
            # Tenta apagar a última linha se for o status anterior do URLScan
            last_line_range = "end-2c linestart", "end-1c"
            last_line = textbox_geral.get(*last_line_range)
            if "URLScan.io: Análise URLScan em andamento" in last_line or "URLScan.io: Análise em andamento" in last_line:
                textbox_geral.delete(*last_line_range)
            textbox_geral.insert("end", f"\n• URLScan.io: {message}")
        except Exception:
            textbox_geral.insert("end", f"\n• URLScan.io: {message}")
        textbox_geral.config(state="disabled")
        textbox_geral.see("end")

    def run_search(self, observable):
        self.append_output(self.output_map["Geral"], f"Iniciando busca para: {observable}...\n\n")
        self.current_links = generate_osint_links(observable)
        self.after(0, self.display_links) 
        
        # 💡 Lista de APIs a serem executadas
        apis_to_run = [
            ("VirusTotal", search_virustotal),
            ("GreyNoise", search_greynoise), 
            ("URLScan.io", lambda obs: search_urlscan(obs, update_callback=self.urlscan_update_callback)), 
            ("Shodan", search_shodan),
            ("AbuseIPDB", search_abuseipdb),
            ("Pulsedive", search_pulsedive),
            ("Whois", search_whois),
        ]
        
        results = {}
        for api_name, api_func in apis_to_run:
            self.after(0, lambda name=api_name: self.append_output(self.output_map["Geral"], f"• Processando {name}..."))
            results[api_name] = api_func(observable)
            self.after(0, lambda: self._update_status_line()) # Atualiza o status de progresso

        # 💡 NOVO: Executa a busca de CVEs se for um IP (usando InternetDB)
        if is_ip(observable):
            self.after(0, lambda: self.append_output(self.output_map["Geral"], f"\n• Processando InternetDB/CVE (Busca detalhada NVD de {MAX_NVD_DETAILS} CVEs)..."))
            results["InternetDB/CVE"] = search_internetdb(observable)
            self.after(0, lambda: self._update_status_line())
        else:
            results["InternetDB/CVE"] = {"Status": "Não aplicável: InternetDB/CVE suporta apenas Endereços IP."}
            
        self.current_results = results
        
        # 3. Formatando Resultados e Atualizando GUI (chamado na thread principal)
        self.after(0, lambda: self.finalize_search(observable, results))
        
    def _update_status_line(self):
        """Remove a última linha de progresso 'Processando...' da aba Geral."""
        textbox_geral = self.output_map["Geral"]
        textbox_geral.config(state="normal")
        try:
            last_line_range = "end-2c linestart", "end-1c"
            last_line = textbox_geral.get(*last_line_range)
            if "Processando" in last_line:
                textbox_geral.delete(*last_line_range)
        except Exception:
            pass # Ignora se a caixa estiver vazia
        textbox_geral.config(state="disabled")

        
    def finalize_search(self, observable, results):
        """Função para atualizar a GUI após a conclusão de todas as buscas."""
        self._update_status_line() # Garante que a última linha de progresso seja removida
        self.append_output(self.output_map["Geral"], f"\n\n--- Relatório Consolidado para: {observable} ---\n\n")
        
        for api_name, data in results.items():
            textbox = self.output_map.get(api_name)
            output_tab = f"--- DETALHES {api_name.upper()} ---\n\n"
            status_geral = ""
            
            if not isinstance(data, dict):
                status_geral = " ERRO: Formato de retorno inesperado."
            
            # 1. Processamento da aba detalhada
            if api_name == "InternetDB/CVE":
                if 'Status' in data and 'ERRO' in data['Status']:
                    output_tab += f"Status: {data['Status']}\n"
                    status_geral = f" ERRO: {data['Status']}"
                elif 'Status' in data and 'Não aplicável' in data['Status']:
                    output_tab += f"Status: {data['Status']}\n"
                    status_geral = "⚠️ Não aplicável (Não é IP)."
                else:
                    cve_details_list = data.get('CVEs Mais Recentes Detalhadas (NVD)', [])
                    total_cves = data.get('Total de CVEs Encontradas', 0)
                    
                    # Cabeçalho da aba detalhada
                    output_tab += f"Total de CVEs Encontradas: {total_cves}\n"
                    output_tab += f"Portas Abertas: {data.get('Portas Abertas (InternetDB)', 'N/A')}\n"
                    output_tab += f"Hostnames: {data.get('Hostnames', 'N/A')}\n"
                    output_tab += f"CPEs: {data.get('CPEs (Softwares Identificados)', 'N/A')}\n"
                    
                    if cve_details_list:
                        output_tab += f"\n--- Detalhes NVD (Top {len(cve_details_list)} CVEs Mais Recentes) ---\n"
                        first_cve_summary = ""
                        for i, cve in enumerate(cve_details_list):
                            output_tab += f"\n[CVE #{i+1}]: {cve.get('ID_CVE', 'N/A')}\n"
                            for k_cve, v_cve in cve.items():
                                if k_cve != 'ID_CVE':
                                    output_tab += f"  - {k_cve}: {v_cve}\n"
                            
                            if i == 0:
                                first_cve_summary = f"CVE Prioritária: {cve.get('ID_CVE')} (CVSS: {cve.get('Severidade (CVSS 3.1)', 'N/A')})"
                                
                        if total_cves > len(cve_details_list):
                            output_tab += f"\nAVISO: Apenas os {len(cve_details_list)} CVEs mais recentes foram detalhados. Total de CVEs: {total_cves}."
                        
                        status_geral = f" OK. {total_cves} CVEs encontradas. {first_cve_summary}"
                    else:
                        status_geral = f" OK. Total de CVEs: {total_cves} (Sem detalhe NVD disponível ou aplicável)."
                        
            else:
                # Filtra campos internos para exibição
                filtered_data = {k: v for k, v in data.items() if k not in ['raw_vulns_list_total', 'CVEs Mais Recentes Detalhadas (NVD)']}
                
                # Exibe dados na aba detalhada
                for key, value in filtered_data.items():
                    output_tab += f"{key}: {value}\n"

                # Lógica para o status geral
                if 'Status' in data:
                    if 'ERRO' in data['Status'] or 'não configurada' in data['Status']:
                        status_geral = f"❌ ERRO/AVISO: {data['Status']}"
                    elif 'Não aplicável' in data['Status']:
                        status_geral = f"⚠️ {data['Status']}"
                    elif 'Nenhuma informação' in data['Status']:
                        status_geral = f"⚠️ Não Encontrado (404/Vazio)."
                    else:
                        status_geral = f"OK. Reputação: {data.get('Veredito de Risco (Geral)', data.get('Reputação Geral (VT)', data.get('Score de Confiança de Abuso', data.get('Risco Geral', data.get('Classificação Geral', 'N/A')))))}"
                else:
                    status_geral = f" OK. Reputação: {data.get('Veredito de Risco (Geral)', data.get('Reputação Geral (VT)', data.get('Score de Confiança de Abuso', data.get('Risco Geral', data.get('Classificação Geral', 'N/A')))))}"

            # 2. Atualiza as caixas de texto
            if textbox:
                self._safe_replace_output(textbox, output_tab)
            self.append_output(self.output_map["Geral"], f"• {api_name}: {status_geral}\n")
            
        self.append_output(self.output_map["Geral"], "\n--- Busca Completa ---")
        self.tabview.set("Geral")
        self.search_button.configure(state="normal", text="Buscar")
        self.analyze_file_button.configure(state="normal", text="Analisar Arquivo") 
        self.save_json_button.configure(state="normal")
        self.analyze_ia_button.configure(state="normal")

    # --- FUNÇÕES HYBRID ANALYSIS (INTEGRAÇÃO GUI) ---
    def open_file_dialog(self):
        file_path = filedialog.askopenfilename(
            title="Selecione o Arquivo para Análise",
            filetypes=[("Todos os Arquivos", "*.*")]
        )
        if file_path:
            self.start_ha_analysis_thread(file_path)

    def start_ha_analysis_thread(self, file_path):
        self.clear_fields()
        self.current_observable = os.path.basename(file_path) # Usa o nome do arquivo
        self.observable_entry.insert(0, self.current_observable) 
        self.search_button.configure(state="disabled") 
        self.analyze_file_button.configure(state="disabled", text="Analisando...")
        self.save_json_button.configure(state="disabled") 
        self.analyze_ia_button.configure(state="disabled")
        ha_textbox = self.output_map["HybridAnalysis"]
        self._safe_replace_output(ha_textbox, f"Iniciando análise de arquivo: {file_path}...\n\n")
        self.tabview.set("HybridAnalysis")
        
        thread = threading.Thread(target=self.run_ha_analysis, args=(file_path,))
        thread.start()

    def ha_update_callback(self, message):
        self.after(0, lambda: self._update_ha_status(message))

    def _update_ha_status(self, message):
        textbox_ha = self.output_map["HybridAnalysis"]
        textbox_geral = self.output_map["Geral"]
        
        # Atualiza a aba HA (substitui o texto para mostrar o progresso)
        self._safe_replace_output(textbox_ha, f"--- HYBRID ANALYSIS ---\n\n{message}")
        
        # Atualiza a aba Geral (mantém apenas a última linha de status de progresso)
        textbox_geral.config(state="normal")
        try:
            last_line_range = "end-2c linestart", "end-1c"
            last_line = textbox_geral.get(*last_line_range)
            if "HybridAnalysis" in last_line:
                textbox_geral.delete(*last_line_range)
            textbox_geral.insert("end", f"\n• HybridAnalysis: {message}")
        except Exception:
            textbox_geral.insert("end", f"\n• HybridAnalysis: {message}")
        textbox_geral.config(state="disabled")
        textbox_geral.see("end")


    def run_ha_analysis(self, file_path):
        ha_result = search_hybrid_analysis(file_path, update_callback=self.ha_update_callback)
        self.after(0, lambda: self.finalize_ha_analysis(ha_result))
        
    def finalize_ha_analysis(self, ha_result):
        ha_textbox = self.output_map["HybridAnalysis"]
        output_tab = "--- DETALHES HYBRID ANALYSIS ---\n\n"
        status_geral = ""
        link_url_ha = None 

        ha_textbox.config(state="normal")
        
        if isinstance(ha_result, dict):
            for key, value in ha_result.items():
                output_tab += f"{key}: {value}\n"
                
                if key.startswith("Link do Relatório") and value and "http" in value:
                    link_url_ha = value
                    
            status_key = ha_result.get('Status')
            if status_key and "ERRO" in status_key:
                status_geral = f" {status_key}"
            elif status_key and "Sucesso na Submissão" in status_key:
                status_geral = f" Submetido (Análise em Fila/Andamento)."
            else:
                status_geral = f" OK. Veredito: {ha_result.get('Veredito HA', 'N/A')}"
        else:
            output_tab += f"ERRO: Formato de retorno inesperado."
            status_geral = " ERRO: Formato inesperado."
            
        self._safe_replace_output(ha_textbox, output_tab) 

        # Adiciona à barra de links rápidos
        if link_url_ha:
            self.current_links['HA Report'] = link_url_ha 
            self.after(0, self.display_links) 
        
        # Atualiza a aba Geral com o resultado final
        self._update_ha_status(status_geral)

        self.search_button.configure(state="normal", text="Buscar")
        self.analyze_file_button.configure(state="normal", text="Analisar Arquivo")
        self.save_json_button.configure(state="normal")
        self.analyze_ia_button.configure(state="normal")
        self.tabview.set("HybridAnalysis")

    # --- FUNÇÕES DE IA E SALVAR ---
    def run_ai_analysis(self):
        if not self.current_results or not self.current_observable:
            self.append_output(self.output_map["Geral"], "\n⚠️ Execute uma busca antes de solicitar a análise de IA.")
            return
        
        # Verifica se as chaves da HA ou URLScan não estão na lista de resultados, se for análise de arquivo.
        is_file_analysis = not is_ip(self.observable_entry.get()) and not ("." in self.observable_entry.get())
        if is_file_analysis and "HybridAnalysis" not in self.current_results:
            self.append_output(self.output_map["Geral"], "\n⚠️ Análise de IA requer um resultado de busca IP/Domínio ou de Arquivo (HybridAnalysis) preenchido.")
            return
            
        self.analyze_ia_button.configure(state="disabled", text="Analisando...")
        self.save_ai_report_button.configure(state="disabled")
        ia_textbox = self.output_map["Análise IA"]
        self._safe_replace_output(ia_textbox, "Processando análise detalhada (Gemini), aguarde...")
        self.tabview.set("Análise IA")
        thread = threading.Thread(target=self._generate_ai_report)
        thread.start()

    def _generate_ai_report(self):
        analysis_text = generate_ai_analysis(self.current_observable, self.current_results)
        self.current_ai_report = analysis_text
        self.after(0, lambda: self._display_ai_report(analysis_text))

    def _display_ai_report(self, analysis_text):
        ia_textbox = self.output_map["Análise IA"]
        
        self.append_output(ia_textbox, f"--- ANÁLISE DETALHADA POR IA (GEMINI 2.5 FLASH) ---\n\n")
        self._safe_replace_output(ia_textbox, f"--- ANÁLISE DETALHADA POR IA (GEMINI 2.5 FLASH) ---\n\n{analysis_text}")

        self.analyze_ia_button.configure(state="normal", text="Analisar c/ IA")
        
        if not isinstance(analysis_text, dict) and "ERRO" not in analysis_text:
            self.save_ai_report_button.configure(state="normal")
            self.append_output(self.output_map["Geral"], "\n✅ Análise de IA concluída. Verifique a aba 'Análise IA'.")
        else:
            status_msg = analysis_text.get('Status', 'ERRO na análise de IA.') if isinstance(analysis_text, dict) else analysis_text
            self.append_output(self.output_map["Geral"], f"\n {status_msg}")
            self.save_ai_report_button.configure(state="disabled")

    def save_results_as_json(self):
        if not self.current_results:
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=f"OSINT_Report_{self.current_observable}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                final_data = {
                    "observable": self.current_observable,
                    "timestamp": datetime.now().isoformat(),
                    "results": self.current_results
                }
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(final_data, f, ensure_ascii=False, indent=4)
                self.append_output(self.output_map["Geral"], f"\n✅ Arquivo JSON salvo com sucesso: {file_path}")
            except Exception as e:
                self.append_output(self.output_map["Geral"], f"\n ERRO ao salvar JSON: {e}")

    def save_ai_report(self):
        if not self.current_ai_report:
            self.append_output(self.output_map["Geral"], "\n⚠️ Nenhum relatório de IA gerado para salvar.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"AI_Analysis_Report_{self.current_observable}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Relatório de Análise de OSINT por IA (Gemini) para: {self.current_observable}\n")
                    f.write(f"Data da Análise: {datetime.now().isoformat()}\n\n")
                    f.write("----------------------------------------------------------------\n\n")
                    f.write(self.current_ai_report)
                self.append_output(self.output_map["Geral"], f"\n✅ Relatório de IA salvo com sucesso: {file_path}")
            except Exception as e:
                self.append_output(self.output_map["Geral"], f"\n ERRO ao salvar Relatório de IA: {e}")


if __name__ == "__main__":
    app = OSINTApp()
    app.mainloop()