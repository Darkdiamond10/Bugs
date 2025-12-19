#!/usr/bin/env python3
import os
import sys
import time
import socket
import ssl
import queue
import threading
import subprocess
import re
import zipfile
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from rich.console import Console

# Initialize colorama
init(autoreset=True)

# Initialize Rich Console
console = Console()

# --- Constants & Configuration ---

# Colors for raw print if needed (prefer Rich where possible)
G = Fore.GREEN
R = Fore.RED
C = Fore.CYAN
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

BANNER = """
[bold magenta]
╔════════════════════════════════════════════╗
║                                            ║
║  ░█▀▀▄ ░█▀▀█ ░█▀▀█ ░█─▄▀                   ║
║  ░█─░█ ░█▄▄█ ░█▄▄▀ ░█▀▄─                   ║
║  ░█▄▄▀ ░█─░█ ░█─░█ ░█─░█                   ║
║                                            ║
║  ░█▀▀▄ ░█▀▀█ ░█▀▀█ ░█▀▀█ ░█▀▀█ ░█▄─░█      ║
║  ░█─░█ ░█▄▄▀ ░█▄▄█ ░█─▄▄ ░█─░█ ░█░█░█      ║
║  ░█▄▄▀ ░█─░█ ░█─░█ ░█▄▄█ ░█▄▄█ ░█──▀█      ║
║                                            ║
╚════════════════════════════════════════════╝
[/bold magenta]
"""

# Global Lock for thread-safe printing
print_lock = threading.Lock()

class ScannerUtils:
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def check_file_exists(filepath):
        return os.path.isfile(filepath)

    @staticmethod
    def print_banner():
        ScannerUtils.clear_screen()
        console.print(BANNER)

    @staticmethod
    def slow_print(text, delay=0.03):
        """Prints text slowly for effect."""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

class NetworkScanner:
    @staticmethod
    def scan_sni(domain, port, timeout=3):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # ssock.do_handshake() # wrap_socket does handshake by default unless do_handshake_on_connect=False
                    cert = ssock.getpeercert()
                    issuer = cert.get('issuer')
                    # Format issuer for display
                    issuer_str = str(issuer)
                    if isinstance(issuer, tuple) or isinstance(issuer, list):
                         # Try to extract common name or organization
                         pass
                    return (True, f"Handshake success | Issuer: {issuer_str}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_ssl(domain, port, timeout=3):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                 with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert() # Might be empty if CERT_NONE and no validation requested?
                    # Actually getpeercert() returns empty dict if validation is off usually, but let's check.
                    # If CERT_NONE, getpeercert() returns nothing unless binary_form=True?
                    # The original code just did ssock.getpeercert().
                    # Let's stick to simple success check.
                    return (True, "SSL connection success")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_proxy(domain, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((domain, port))
            connect_req = f"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com\r\n\r\n"
            sock.send(connect_req.encode())
            resp = sock.recv(1024).decode(errors='ignore')
            sock.close()
            if '200 Connection established' in resp or 'HTTP/1.1 200' in resp:
                return (True, 'Proxy OK')
            return (False, 'Proxy connection failed')
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_http(domain, port, timeout=3):
        try:
            url = f"http://{domain}:{port}"
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f"Redirect 302 ignored | Server: {server}")
            return (True, f"{resp.status_code} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_https(domain, port, timeout=3):
        try:
            url = f"https://{domain}:{port}"
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f"Redirect 302 ignored | Server: {server}")
            return (True, f"{resp.status_code} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))

class CIDRScanner:
    def __init__(self, port, threads, output_file):
        self.port = port
        self.threads = threads
        self.output_file = output_file
        self.q = queue.Queue()
        self.total = 0
        self.progress = 0
        self.start_time = time.time()
        self.cdn_keywords = ['cloudflare', 'cloudfront', 'akamai', 'google', 'fastly', 'openresty', 'tengine', 'varnish', 'google frontend', 'googlefrontend']

    def load_targets(self, ranges_list):
        for net in ranges_list:
            try:
                # Use ipaddress module instead of ipcalc
                network = ipaddress.IPv4Network(net, strict=False)
                for ip in network:
                    self.q.put(str(ip))
                    self.total += 1
            except Exception as e:
                console.print(f"{R}[!] Invalid range: {net} ({e}){RESET}")

    def check_ip(self, ip):
        url = f"https://{ip}" if self.port == 443 else f"http://{ip}:{self.port}"
        try:
            r = requests.get(url, timeout=1.5, allow_redirects=False, verify=False)
            server = r.headers.get('server', 'unknown').lower()
            cf_ray = r.headers.get('cf-ray', '-')
            status = r.status_code
        except:
            server = 'no-response'
            cf_ray = '-'
            status = 0

        # Logic from original script: Ignore 302/307
        if status in (302, 307):
            with print_lock:
                console.print(f"{YELLOW}[{self.progress}/{self.total}] {ip:<15} | {status:<3} | {server:<20} | CF-RAY: {cf_ray} [IGNORED]{RESET}")
            self.progress += 1
            return

        is_cdn = any(cdn in server for cdn in self.cdn_keywords)

        # Save valid responses
        # Valid status codes from original script
        valid_codes = [200, 201, 202, 204, 206, 300, 301, 303, 304, 400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504]

        if status in valid_codes:
            result = f"{ip}\t{status}\t{server}\tCF-RAY: {cf_ray}\n"
            with open(self.output_file, 'a') as f:
                f.write(result)

        # Output to screen
        color = G if is_cdn else (C if status != 0 else R)
        with print_lock:
            console.print(f"{color}[{self.progress}/{self.total}] {ip:<15} | {status:<3} | {server:<20} | CF-RAY: {cf_ray}{RESET}")

        self.progress += 1

    def worker(self):
        while True:
            ip = self.q.get()
            if ip is None:
                return
            self.check_ip(ip)
            self.q.task_done()

    def start(self, ranges_list):
        console.print(f"{YELLOW}→ Preparing scan with {self.threads} threads on port {self.port}...{RESET}")
        self.load_targets(ranges_list)

        workers = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            workers.append(t)

        self.q.join()

        # Stop workers
        for _ in workers:
            self.q.put(None)
        for t in workers:
            t.join()

        duration = int(time.time() - self.start_time)
        console.print(f"\n{MAGENTA}[✓] Scan finished in {duration}s. Total IPs: {self.total}{RESET}")


class SubdomainRecon:
    @staticmethod
    def extract_subdomains(domain, virustotal_api_key=None):
        console.print(f"[cyan]Extracting subdomains for {domain} from multiple sources...[/cyan]")
        all_subs = []
        all_subs.extend(SubdomainRecon.run_subfinder(domain))
        all_subs.extend(SubdomainRecon.get_crtsh_subdomains(domain))
        all_subs.extend(SubdomainRecon.get_alienvault_subdomains(domain))
        all_subs.extend(SubdomainRecon.get_dnsdumpster_subdomains(domain))

        # Sublist3r
        try:
            import sublist3r
            console.print(f"[cyan]Extracting subdomains from {domain} using sublist3r...[/cyan]")
            subs = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            if subs:
                all_subs.extend(subs)
        except ImportError:
            pass # sublist3r not installed
        except Exception as e:
            console.print(f"[red]Error extracting subdomains with sublist3r: {e}[/red]")

        if virustotal_api_key:
            all_subs.extend(SubdomainRecon.get_virustotal_subdomains(domain, virustotal_api_key))

        unique_subs = list(set(all_subs))
        console.print(f"[green]Found {len(unique_subs)} unique subdomains for {domain}[/green]")
        return unique_subs

    @staticmethod
    def run_subfinder(domain):
        """Run subfinder as external tool"""
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                subs = result.stdout.splitlines()
                return list(set(subs))
            return []
        except Exception as e:
            console.print(f"[red]subfinder error: {e}[/red]")
            return []

    @staticmethod
    def get_crtsh_subdomains(domain):
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return []
            data = response.json()
            subs = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                for name in name_value.split('\n'):
                    if domain in name:
                        subs.add(name.strip())
            return list(subs)
        except Exception as e:
            console.print(f"[yellow]crt.sh warning: {e}[/yellow]")
            return []

    @staticmethod
    def get_alienvault_subdomains(domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        subs = []
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get('passive_dns', []):
                    name = record.get('hostname')
                    if name and domain in name:
                        subs.append(name)
            return list(set(subs))
        except Exception as e:
            console.print(f"[yellow]AlienVault warning: {e}[/yellow]")
            return []

    @staticmethod
    def get_dnsdumpster_subdomains(domain):
        url = 'https://dnsdumpster.com/'
        session = requests.Session()
        subs = []
        try:
            resp = session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            token = csrf['value'] if csrf else ''
            headers = {'Referer': url, 'User-Agent': 'Mozilla/5.0', 'X-CSRFToken': token}
            data = {'csrfmiddlewaretoken': token, 'targetip': domain}
            post_resp = session.post(url, headers=headers, data=data, timeout=20)
            post_soup = BeautifulSoup(post_resp.text, 'html.parser')
            tables = post_soup.find_all('table')
            for table in tables:
                for row in table.find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) > 0:
                        sub = cols[0].text.strip()
                        if domain in sub:
                             subs.append(sub)
            return list(set(subs))
        except Exception as e:
            console.print(f"[yellow]DNSDumpster warning: {e}[/yellow]")
            return []

    @staticmethod
    def get_virustotal_subdomains(domain, api_key):
        if not api_key:
            return []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {'x-apikey': api_key}
        subs = []
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('data', []):
                    subs.append(item['id'])
            return list(set(subs))
        except Exception as e:
            console.print(f"[yellow]VirusTotal warning: {e}[/yellow]")
            return []

    @staticmethod
    def save_domains_to_file(domains, filename):
        unique = sorted(set(domains))
        with open(filename, 'w') as f:
            for d in unique:
                f.write(d + '\n')
        console.print(f"[green]Saved {len(unique)} unique domains to '{filename}'[/green]")

    @staticmethod
    def gather_ip(domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

class ApkAnalyzer:
    @staticmethod
    def unzip_apk(apk_path, extract_to):
        if not os.path.exists(apk_path):
            console.print(f"{R}[!] Error: APK file '{apk_path}' not found!{RESET}")
            return False
        if os.path.exists(extract_to):
            console.print(f"{YELLOW}[!] Warning: folder '{extract_to}' exists, removing...{RESET}")
            import shutil
            shutil.rmtree(extract_to)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            console.print(f"{G}[+] APK extracted to: {extract_to}{RESET}")
            return True
        except Exception as e:
            console.print(f"{R}[!] Error extracting APK: {e}{RESET}")
            return False

    @staticmethod
    def read_all_files(folder):
        texts = []
        for root, dirs, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        texts.append(f.read())
                except:
                    pass
        return texts

    @staticmethod
    def extract_domains_urls(texts):
        # Regex to match URLs: http or https, followed by non-whitespace/quote characters
        pattern_url = re.compile(r'https?://[^\s"\'<>]+')
        pattern_domain = re.compile(r'(?<=://)?([a-zA-Z0-9.-]+\.(?:com|net|org|sa|cn|io|co|app|info|biz|online|tech|store))')
        urls = set()
        domains = set()
        for text in texts:
            for url in pattern_url.findall(text):
                urls.add(url.strip())
            for dom in pattern_domain.findall(text):
                domains.add(dom.strip())
        return (urls, domains)

    @staticmethod
    def extract_keywords(texts):
        keywords = ['cdn', 'api', 'host', 'endpoint', 'payment', 'pay', 'billing', 'checkout', '.alicdn', '.mobily']
        found = set()
        for text in texts:
            text_lower = text.lower()
            for kw in keywords:
                if kw in text_lower:
                    found.add(kw)
        return found

    @staticmethod
    def extract_payment_urls(urls):
        payment_keys = ['pay', 'payment', 'checkout', 'billing']
        payments = set()
        for url in urls:
            for key in payment_keys:
                if key in url.lower():
                    payments.add(url)
        return payments

    @staticmethod
    def check_cdn(domain):
        cdn_keywords = ['alicdn', 'akamai', 'cloudflare', 'fastly', 'amazon', 'edgekey', 'cdn']
        for kw in cdn_keywords:
            if kw in domain.lower():
                return True
        return False

    @staticmethod
    def save_results(folder, urls, domains, keywords, cdn_domains, payments):
        os.makedirs(folder, exist_ok=True)

        def write_list(fname, data):
             with open(os.path.join(folder, fname), 'w') as f:
                for item in sorted(data):
                    f.write(item + '\n')

        write_list('urls.txt', urls)
        write_list('domains.txt', domains)
        write_list('keywords.txt', keywords)
        write_list('cdn_domains.txt', cdn_domains)
        write_list('payment_urls.txt', payments)

    @staticmethod
    def run():
        ScannerUtils.print_banner()
        console.print(f"{R}\n    ☠️☠️☠️ APK CDN HUNTER ☠️☠️☠️\n    🔥 SCANNING APK FILE FOR SECRET DOMAINS 🔥\n    {RESET}")
        apk_path = console.input(f"{C}🔍 Enter APK file path: {RESET}").strip()
        result_folder = console.input(f"{C}💾 Enter folder name to save results: {RESET}").strip()

        ScannerUtils.slow_print(f"{MAGENTA}[*] Extracting APK file ...{RESET}")
        if not ApkAnalyzer.unzip_apk(apk_path, result_folder + '_extracted'):
            return

        ScannerUtils.slow_print(f"{MAGENTA}[*] Reading all files ...{RESET}")
        texts = ApkAnalyzer.read_all_files(result_folder + '_extracted')

        ScannerUtils.slow_print(f"{MAGENTA}[*] Extracting URLs and domains ...{RESET}")
        urls, domains = ApkAnalyzer.extract_domains_urls(texts)

        ScannerUtils.slow_print(f"{MAGENTA}[*] Searching for important keywords ...{RESET}")
        keywords = ApkAnalyzer.extract_keywords(texts)

        ScannerUtils.slow_print(f"{MAGENTA}[*] Extracting payment gateway URLs ...{RESET}")
        payments = ApkAnalyzer.extract_payment_urls(urls)

        ScannerUtils.slow_print(f"{MAGENTA}[*] Analyzing domains and checking for CDN ...{RESET}")
        cdn_domains = set()
        for d in domains:
            if ApkAnalyzer.check_cdn(d):
                cdn_domains.add(d)

        ScannerUtils.slow_print(f"{G}[✔] Saving results ...{RESET}")
        ApkAnalyzer.save_results(result_folder, urls, domains, keywords, cdn_domains, payments)

        console.print(f"{YELLOW}\n[✔] Scan complete! Results saved in folder: {result_folder}{RESET}")
        console.print(f"{YELLOW}Check files:\n - urls.txt\n - domains.txt\n - keywords.txt\n - cdn_domains.txt\n - payment_urls.txt\n{RESET}")
        console.input('Press Enter to return to main menu...')


class DNSScanner:
    @staticmethod
    def check_dns(ip, output_file):
        try:
            sock = socket.socket(so
