# NetSentinel — execute esta única célula no Google Colab.
# Instala automaticamente o necessário (não precisa de Secrets/Gemini).
import sys, subprocess, importlib.util, shutil
for pacote, modulo in [("requests", "requests"), ("rich", "rich"), ("pandas", "pandas")]:
    if importlib.util.find_spec(modulo) is None:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pacote])

# Digite o endereço IP ou domínio de uma máquina/rede que você tem autorização para testar.
ALVO = input("IP ou domínio do servidor autorizado: ").strip()
if not ALVO:
    raise ValueError("Informe um endereço IP ou domínio para executar a análise.")

# Reconhecimento + Nmap automaticamente, sem configurar modos.
MODO = "-scan"
PESQUISA_CVE = ""  # opcional: produto/versão para consultar NVD

if shutil.which("nmap") is None:
    print("Instalando Nmap automaticamente no Colab...")
    subprocess.run(["apt-get", "update", "-qq"], check=True)
    subprocess.run(["apt-get", "install", "-y", "-qq", "nmap"], check=True)


import sys
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
import socket
import requests
import csv
from datetime import datetime
from urllib.parse import urlparse

# Rich: biblioteca para deixar o terminal organizado e colorido
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Cria o console responsável pelas mensagens coloridas
console = Console()
inventario = []

# True = simula o comando sem executar o Nmap
# False = executa a varredura real
simulacao = False


# ============================================================
# INTERFACE INICIAL
# ============================================================

def mostrar_banner():
    # Exibe a identidade visual do NetSentinel
    banner = r"""
 _   _      _   ____             _   _            _
| \ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___| |
|  \| |/ _ \ __\___ \ / _ \ '_ \| __| | '_ \ / _ \ |
| |\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/ |
|_| \_|\___|\__|____/ \___|_| |_|\__|_|_| |_|\___|_|

                  CREATED BY PH
"""

    console.print(
        Panel(
            f"[bold cyan]{banner}[/bold cyan]",
            title="[bold green]NETSENTINEL[/bold green]",
            subtitle="[white]Network Scanner | Cybersecurity[/white]",
            border_style="cyan"
        )
    )


# ============================================================
# MENU DE AJUDA
# ============================================================

def mostrar_ajuda():
    # Cria a tabela com os comandos disponíveis
    tabela = Table(title="COMANDOS DO NETSENTINEL")

    tabela.add_column("Comando", style="cyan")
    tabela.add_column("Descrição", style="white")

    tabela.add_row("-ftv", "Varredura de baixo impacto")
    tabela.add_row("-scan", "Scan das 1000 portas TCP mais comuns")
    tabela.add_row("-full", "Scan completo, serviços e sistema operacional")
    tabela.add_row("-recon", "DNS, subdomínios, IP e servidor HTTP (sem Nmap)")
    tabela.add_row("-cve", "Pesquisar CVEs por produto/versão informados")
    tabela.add_row("--help", "Mostrar comandos disponíveis")

    console.print(tabela)


# ============================================================
# INVESTIGAÇÃO DE DOMÍNIO E INVENTÁRIO
# ============================================================

def normalizar_alvo(alvo):
    # Aceita IP, domínio ou URL. Retorna hostname sem protocolo/caminho.
    partes = urlparse(alvo if "://" in alvo else "//" + alvo)
    host = partes.hostname
    if not host or any(ch.isspace() for ch in host):
        raise ValueError("Domínio ou IP inválido.")
    return host


def cadastrar_inventario(host, ip, server, content_type):
    inventario.append({
        "hostname": host,
        "ip": ip,
        "server": server,
        "type": content_type
    })
    console.print(f"[green]Ativo {host} registrado com sucesso.[/green]")


def salvar_inventario(caminho="inventario_netsentinel.csv"):
    if not inventario:
        return
    with open(caminho, "w", newline="", encoding="utf-8") as arquivo:
        escritor = csv.DictWriter(arquivo, fieldnames=["hostname", "ip", "server", "type"])
        escritor.writeheader()
        escritor.writerows(inventario)
    console.print(f"[green]Inventário salvo em {caminho}[/green]")


def resolver_ip(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as erro:
        console.print(f"[red]Não foi possível resolver {host}: {erro}[/red]")
        return None


def investigar_alvo(alvo):
    host = normalizar_alvo(alvo)
    console.print("\n[bold cyan]=========== Resolução DNS =============[/bold cyan]")
    ip = resolver_ip(host)
    if not ip:
        return None
    console.print(f"Domínio/host: {host}\nIP do servidor: {ip}")

    # Só tenta nomes como www e api para domínios, não para endereços IP.
    try:
        ipaddress.ip_address(host)
        eh_ip = True
    except ValueError:
        eh_ip = False

    if not eh_ip:
        console.print("\n[bold cyan]=========== Subdomínios =============[/bold cyan]")
        for sub in ["www", "mail", "ftp", "api", "blog"]:
            subhost = f"{sub}.{host}"
            endereco = resolver_ip_silencioso(subhost)
            if endereco:
                console.print(f"{subhost} -> {endereco}")
            else:
                console.print(f"[dim]{subhost} -> não resolvido[/dim]")

    console.print("\n[bold cyan]=========== Servidor HTTP =============[/bold cyan]")
    resposta = None
    for protocolo in ["https", "http"]:
        try:
            resposta = requests.get(f"{protocolo}://{host}", timeout=10)
            console.print(f"URL: {resposta.url}\nStatus HTTP: {resposta.status_code}")
            break
        except requests.RequestException as erro:
            console.print(f"[yellow]Falha em {protocolo.upper()}: {erro}[/yellow]")

    server = "Não informado"
    content_type = "Não informado"
    if resposta is not None:
        for chave, valor in resposta.headers.items():
            console.print(f"{chave}: {valor}")
        server = resposta.headers.get("Server", "Não informado")
        content_type = resposta.headers.get("Content-Type", "Não informado")
    else:
        console.print("[yellow]Não foi possível identificar os cabeçalhos HTTP.[/yellow]")

    console.print(Panel(f"[cyan]IP:[/cyan] {ip}\n[cyan]Servidor HTTP:[/cyan] {server}\n[cyan]Content-Type:[/cyan] {content_type}", title="INFORMAÇÕES DO SERVIDOR"))
    cadastrar_inventario(host, ip, server, content_type)
    salvar_inventario()
    return ip


def resolver_ip_silencioso(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def classificar_cvss(nota):
    if nota is None:
        return "NÃO INFORMADO"
    if nota == 0:
        return "NENHUMA"
    if nota < 4:
        return "BAIXA"
    if nota < 7:
        return "MÉDIA"
    if nota < 9:
        return "ALTA"
    return "CRÍTICA"


def consultar_cves(termo):
    # A NVD pesquisa pelo termo. Uma correspondência não prova
    # que o servidor analisado esteja vulnerável.
    console.print(f"\n[cyan]Pesquisando na NVD: {termo}[/cyan]")
    try:
        resposta_nvd = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": termo, "resultsPerPage": 5},
            headers={"User-Agent": "NetSentinel/1.0 (educational research)"},
            timeout=15
        )
        resposta_nvd.raise_for_status()
        dados = resposta_nvd.json()
        vulnerabilidades = dados.get("vulnerabilities", [])
        if not vulnerabilidades:
            console.print("[yellow]Nenhuma CVE encontrada para esse termo.[/yellow]")
            return
        tabela = Table(title="CVE - RESULTADOS DA PESQUISA (NÃO CONFIRMADOS)")
        tabela.add_column("CVE")
        tabela.add_column("CVSS")
        tabela.add_column("Classificação")
        for item in vulnerabilidades:
            cve = item.get("cve", {})
            metricas = cve.get("metrics", {})
            nota = None
            for versao in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metricas.get(versao):
                    nota = metricas[versao][0].get("cvssData", {}).get("baseScore")
                    break
            tabela.add_row(cve.get("id", "?"), str(nota) if nota is not None else "N/D", classificar_cvss(nota))
        console.print(tabela)
        console.print("[yellow]Atenção: CVEs encontradas por palavra-chave precisam ser verificadas contra produto e versão reais.[/yellow]")
    except (requests.RequestException, ValueError, KeyError) as erro:
        console.print(f"[red]Falha ao consultar a NVD: {erro}[/red]")


# ============================================================
# CONFIGURAÇÃO DOS SCANS
# ============================================================

def configurar_scan(comando, alvo):

    if comando == "-ftv":
        # -sT: realiza conexões TCP completas
        # -T2: utiliza temporização mais conservadora
        # -p: seleciona portas específicas
        # Não garante invisibilidade ou ausência de detecção
        nome = "LOW IMPACT SCAN"

        argumentos = [
            "-sT",
            "-T2",
            "-p", "21,22,23,80,443,445,3389"
        ]

    elif comando == "-scan":
        # -sT: realiza conexões TCP completas
        # --top-ports: verifica as portas mais frequentes
        nome = "STANDARD SCAN"

        argumentos = [
            "-sT",
            "--top-ports", "1000"
        ]

    elif comando == "-full":
        # -sS: TCP SYN Scan (normalmente exige root)
        # -PE: utiliza ICMP Echo na descoberta do host
        # -p-: verifica todas as 65535 portas TCP
        # -sV: identifica serviços e versões
        # -O: tenta identificar o sistema operacional
        # -sC: executa os scripts NSE padrão
        nome = "FULL HOST SCAN"

        argumentos = [
            "-sS",
            "-PE",
            "-p-",
            "-sV",
            "-O",
            "-sC"
        ]

    # -oX -: retorna o resultado em XML na saída padrão
    # O XML facilita a leitura dos dados pelo Python
    comando_nmap = ["nmap"] + argumentos + ["-oX", "-", alvo]

    return nome, comando_nmap


# ============================================================
# PROCESSAMENTO DOS RESULTADOS
# ============================================================

def mostrar_resultados(xml):

    # Converte o XML produzido pelo Nmap para uma estrutura
    # que o Python consegue percorrer
    raiz = ET.fromstring(xml)

    hosts = raiz.findall("host")

    if not hosts:
        console.print("[yellow]Nenhum host encontrado.[/yellow]")
        return

    for host in hosts:

        # Obtém o status do host: up ou down
        status = host.find("status")
        estado = status.get("state", "unknown") if status is not None else "unknown"

        # Procura o endereço IP no resultado
        ip = "Desconhecido"

        for endereco in host.findall("address"):
            if endereco.get("addrtype") in ["ipv4", "ipv6"]:
                ip = endereco.get("addr", "Desconhecido")
                break

        # Procura a latência medida pelo Nmap
        latencia = "Não disponível"
        tempos = host.find("times")

        if tempos is not None:
            valor = tempos.get("srtt")

            if valor is not None:
                # O Nmap informa srtt em microssegundos
                latencia = f"{int(valor) / 1000:.2f} ms"

        # Procura a estimativa de sistema operacional
        sistema = "Não identificado"
        osmatch = host.find("./os/osmatch")

        if osmatch is not None:
            sistema = osmatch.get("name", "Desconhecido")

        # Exibe informações do host dentro de um painel
        console.print(
            Panel(
                f"[cyan]IP:[/cyan] {ip}\n"
                f"[cyan]Status:[/cyan] {estado.upper()}\n"
                f"[cyan]Latência:[/cyan] {latencia}\n"
                f"[cyan]Sistema operacional:[/cyan] {sistema}",
                title="[bold green]INFORMAÇÕES DO HOST[/bold green]",
                border_style="green"
            )
        )

        # Cria tabela de portas
        tabela = Table(title="PORTAS E SERVIÇOS")

        tabela.add_column("Porta", style="cyan")
        tabela.add_column("Status", style="green")
        tabela.add_column("Serviço", style="yellow")
        tabela.add_column("Versão", style="white")

        abertas = 0

        # Percorre as portas identificadas no XML
        for porta in host.findall("./ports/port"):

            numero = porta.get("portid", "?")
            protocolo = porta.get("protocol", "tcp")

            estado_porta = porta.find("state")
            status_porta = (
                estado_porta.get("state", "unknown")
                if estado_porta is not None else "unknown"
            )

            # Mostra somente portas abertas
            if status_porta != "open":
                continue

            abertas += 1

            # Obtém o serviço e sua possível versão
            servico = porta.find("service")

            nome_servico = "Desconhecido"
            versao = "-"

            if servico is not None:
                nome_servico = servico.get("name", "Desconhecido")

                produto = servico.get("product", "")
                numero_versao = servico.get("version", "")

                versao = f"{produto} {numero_versao}".strip() or "-"

            tabela.add_row(
                f"{numero}/{protocolo}",
                status_porta.upper(),
                nome_servico,
                versao
            )

        if abertas > 0:
            console.print(tabela)
        else:
            console.print(
                "[yellow]Nenhuma porta aberta identificada.[/yellow]"
            )

        # Mostra um resumo no final
        console.print(
            Panel(
                f"[green]Portas abertas: {abertas}[/green]\n"
                f"[cyan]Status do host: {estado.upper()}[/cyan]\n"
                "[green]Análise concluída![/green]",
                title="[bold cyan]RESUMO DA VARREDURA[/bold cyan]",
                border_style="cyan"
            )
        )


# ============================================================
# EXECUÇÃO DO NMAP
# ============================================================

def executar_scan(comando, alvo):
    try:
        host = normalizar_alvo(alvo)
    except ValueError as erro:
        console.print(f"[red]{erro}[/red]")
        return

    # Primeiro identifica o IP e o servidor, depois usa o IP no Nmap.
    ip = investigar_alvo(host)
    if not ip:
        return
    alvo = ip

    # Prepara o comando de acordo com o modo escolhido
    nome, comando_nmap = configurar_scan(comando, alvo)

    console.print(
        Panel(
            f"[green]IP válido:[/green] {alvo}\n"
            f"[yellow]Modo:[/yellow] {nome}\n"
            f"[cyan]Simulação:[/cyan] {simulacao}",
            title="CONFIGURAÇÃO DO SCAN",
            border_style="blue"
        )
    )

    console.print(
        "[cyan]Comando preparado:[/cyan]",
        " ".join(comando_nmap)
    )

    # Se a simulação estiver ativa, não executa o Nmap
    if simulacao:
        console.print(
            Panel(
                "[yellow]Nenhuma varredura foi executada.[/yellow]\n"
                "[green]Configuração validada com sucesso![/green]",
                title="MODO SIMULAÇÃO",
                border_style="yellow"
            )
        )
        return

    try:
        # Executa o Nmap e captura stdout e stderr
        with console.status(
            "[bold yellow]Executando varredura...[/bold yellow]",
            spinner="dots"
        ):
            resultado = subprocess.run(
                comando_nmap,
                capture_output=True,
                text=True,
                timeout=600
            )

        # returncode 0 indica que o Nmap terminou sem erro
        if resultado.returncode == 0:

            console.print(
                "[bold green][+] Varredura finalizada![/bold green]"
            )

            # Processa o XML e organiza os resultados
            mostrar_resultados(resultado.stdout)

        else:
            console.print("[bold red][-] Erro no Nmap![/bold red]")
            console.print(resultado.stderr or resultado.stdout)

    except FileNotFoundError:
        # Ocorre quando o Nmap não está instalado ou no PATH
        console.print("[red]Nmap não encontrado![/red]")

    except subprocess.TimeoutExpired:
        # Interrompe a execução se ultrapassar 600 segundos
        console.print("[red]Tempo limite da varredura excedido![/red]")

    except ET.ParseError:
        # Trata uma resposta XML inválida ou incompleta
        console.print("[red]Erro ao interpretar o XML do Nmap![/red]")




# Execução automática no Colab: basta inserir o IP/domínio no campo de entrada.
mostrar_banner()
try:
    alvo_normalizado = normalizar_alvo(ALVO)
    console.print("\n[bold]Reconhecimento + varredura TCP[/bold]")
    executar_scan(MODO, alvo_normalizado)
except (ValueError, OSError) as erro:
    console.print(f"[red]Falha na investigação: {erro}[/red]")

if PESQUISA_CVE.strip():
    consultar_cves(PESQUISA_CVE.strip())

console.print("\n[bold]Demonstração CVSS:[/bold]")
for nota in [3.1, 5.4, 7.8, 9.4]:
    console.print(f"{nota} → {classificar_cvss(nota)}")

if inventario:
    try:
        import pandas as pd
        from IPython.display import display
        display(pd.DataFrame(inventario))
    except ImportError:
        pass
    console.print("[green]Relatório gerado: inventario_netsentinel.csv[/green]")
    try:
        from google.colab import files
        files.download("inventario_netsentinel.csv")
    except ImportError:
        pass
