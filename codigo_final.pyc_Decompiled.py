# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2025-12-18 20:05:28 UTC (1766088328)

import os
import ipcalc
import queue
import sys
import socket
import ssl
import requests
import concurrent.futures
import threading
import time
import subprocess
from bs4 import BeautifulSoup
import re
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from colorama import Fore
import zipfile
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from rich.console import Console
console = Console()
import pyfiglet
from colorama import Fore, Style
G = '[32m'
R = '[31m'
C = '[36m'
YELLOW = '[93m'
MAGENTA = '[35m'
RESET = '[0m'
try:
    import sublist3r
except ImportError:
    pass  # postinserted
else:  # inserted
    console = Console()
    lock = threading.Lock()
    BANNER = '\n[bold magenta]\n╔══════════════════════════════════════════════════════╗\n║ ░█▀▀█ ░█▀▀█ ▀█▀ ░█▀▀█ ░█▀▀█ ░█▄─░█ ░█▀▀▀ ░█▀▀█ ░█▀▀█ ║\n║ ░█▄▄█ ░█▄▄█ ░█─ ░█─▄▄ ░█▄▄█ ░█░█░█ ░█▀▀▀ ░█▄▄▀ ░█▄▄▀ ║\n║ ░█─░█ ░█─░█ ▄█▄ ░█▄▄█ ░█─░█ ░█──▀█ ░█▄▄▄ ░█─░█ ░█─░█ ║\n║                                                      ║\n║   ( █▀▀ █░█ █▀█ █▀▄▀█   █▀▄▀█ █▀▀ ▀█▀ █▀█ █▀▀ █▀▀█ )   ║\n║   ( ▀▀█ █▀█ █▄█ █░▀░█   █░▀░█ █▄▄ ░█░ █▀▄ █▄▄ █▄▄▀ )   ║\n║                                                      ║\n║    █▀▀ █▀▀█ ░█▀▀█ ░█▀▀▄ ░█▀▀█ ░█▀▀█ ░█▀▀▀ ░█▀▀█       ║\n║    █░░ █▄▄▀ ░█▄▄█ ░█─░█ ░█▄▄▀ ░█▄▄█ ░█▀▀▀ ░█▄▄▀       ║\n║    ▀▀▀ ▀░▀▀ ░█─░█ ░█▄▄▀ ░█─░█ ░█─░█ ░█▄▄▄ ░█─░█       ║\n║                                                      ║\n║    𝗦𝗘𝗖𝗥𝗘𝗧 𝗡𝗘𝗧  ⋆ ⚡🏴‍☠️                              ║\n║    BY: MrPYTHON 🏴‍☠️                                ║\n║    Telegram: https://t.me/SECRET1NET                ║\n╚══════════════════════════════════════════════════════╝\n[/bold magenta]\n'

    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    def check_file_exists(filename):
        return os.path.isfile(filename)

    def scan_sni(domain, port, timeout=3):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                pass  # postinserted
        except Exception as e:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.do_handshake()
                    cert = ssock.getpeercert()
                    issuer = cert.get('issuer', 'Unknown')
                    return (True, f'Handshake success | Issuer: {issuer}')
                return (False, str(e))

    def scan_ssl(domain, port, timeout=3):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                pass  # postinserted
        except Exception as e:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = cert.get('issuer', 'Unknown')
                    return (True, f'SSL connection success | Issuer: {issuer}')
                return (False, str(e))

    def scan_proxy(domain, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((domain, port))
            connect_req = 'CONNECT google.com:443 HTTP/1.1\r\nHost: google.com\r\n\r\n'
            sock.send(connect_req.encode())
            resp = sock.recv(1024).decode(errors='ignore')
            sock.close()
            if '200 Connection established' in resp or 'HTTP/1.1 200' in resp:
                return (True, 'Proxy OK')
        except Exception as e:
            pass  # postinserted
        else:  # inserted
            pass  # postinserted
        return (False, 'Proxy connection failed')
            return (False, str(e))
        else:  # inserted
            pass

    def scan_http(domain, port, timeout=3):
        try:
            url = f'http://{domain}:{port}'
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f'Redirect 302 ignored | Server: {server}')
            return (True, f'{resp.status_code} OK | Server: {server}')
        except Exception as e:
            return (False, str(e))
        else:  # inserted
            pass

    def scan_https(domain, port, timeout=3):
        try:
            url = f'https://{domain}:{port}'
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f'Redirect 302 ignored | Server: {server}')
            return (True, f'{resp.status_code} OK | Server: {server}')
        except Exception as e:
            return (False, str(e))
        else:  # inserted
            pass
            pass
    lock = threading.Lock()

    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    def check_file_exists(path):
        return os.path.isfile(path)

    def scan_cidr_flow():
        clear_screen()
        print(f'{MAGENTA}==== SCAN CIDR ===={RESET}')
        choice = input('Choose scan mode:\n1) Single range\n2) Ranges from file\nEnter choice (1 or 2): ').strip()
        while choice not in ['1', '2']:
            choice = input('Invalid choice. Enter 1 or 2: ').strip()
        if choice == '1':
            ip_range = input('Enter single IP range (e.g. 192.168.1.0/24): ').strip()
            ranges = [ip_range]
        else:  # inserted
            file_path = input('Enter file path containing IP ranges: ').strip()
            while not check_file_exists(file_path):
                print('File not found. Try again.')
                file_path = input('Enter file path containing IP ranges: ').strip()
            with open(file_path, 'r') as f:
                ranges = [line.strip() for line in f if line.strip()]
        port_str = input('Enter port to scan (80 or 443): ').strip()
        while port_str not in ['80', '443']:
            port_str = input('Invalid port. Enter 80 or 443: ').strip()
        port = int(port_str)
        output_file = input('Enter output filename for results (e.g. results.txt): ').strip()
        if not output_file:
            output_file = 'results.txt'
        threads_str = input('Enter number of threads (default 150): ').strip()
        threads = int(threads_str) if threads_str.isdigit() else 150

        class CustomCDNScanner(*, CustomCDNScanner(), scanner=scanner.start(threads)):
            def __init__(self):
                self.q = queue.Queue()
                self.total = 0
                self.progress = 1
                self.start_time = time.time()

            def scan_worker(self):
                while True:
                    ip = self.q.get()
                    if ip is None:
                        return
                    self.check_ip(str(ip))
                    self.q.task_done()

            def check_ip(self, ip):
                url = f'https://{ip}' if port == 443 else f'http://{ip}:{port}'
                try:
                    r = requests.get(url, timeout=1.5, allow_redirects=False)
                    server = r.headers.get('server', 'unknown').lower()
                    cf_ray = r.headers.get('cf-ray', '-')
                    status = r.status_code
                except:
                    server = 'no-response'
                    cf_ray = '-'
                    status = 0
                else:  # inserted
                    pass  # postinserted
                if status in (302, 307):
                    with lock:
                        print(f'{YELLOW}[{self.progress}/{self.total}] {ip:<15} | {status:<3} | {server:<20} | CF-RAY: {cf_ray} [IGNORED]{RESET}')
                    self.progress += 1
                    return
                result = f'{ip}\t{status}\t{server}\tCF-RAY: {cf_ray}\n'
                cdn_keywords = ['cloudflare', 'cloudfront', 'akamai', 'google', 'fastly', 'openresty', 'tengine', 'varnish', 'google frontend', 'googlefrontend']
                is_cdn = any((cdn in server for cdn in cdn_keywords))
                if status in [200, 201, 202, 204, 206, 300, 301, 303, 304, 400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504]:
                    with open(output_file, 'a') as f:
                        f.write(result)
                color = G if is_cdn else C if status!= 0 else R
                with lock:
                    print(f'{color}[{self.progress}/{self.total}] {ip:<15} | {status:<3} | {server:<20} | CF-RAY: {cf_ray}{RESET}')
                self.progress += 1

            def load_targets(self, ranges_list):
                for net in ranges_list:
                    try:
                        for ip in ipcalc.Network(net):
                            self.q.put(ip)
                            self.total += 1
                    except Exception as e:
                        pass  # postinserted
                    print(f'{R}[!] Invalid range: {net} ({e}){RESET}')
                    continue

            def start(self, threads):
                print(f'{YELLOW}→ Preparing scan with {threads} threads on port {port}...{RESET}')
                self.load_targets(ranges)
                workers = []
                for _ in range(threads):
                    t = threading.Thread(target=self.scan_worker)
                    t.daemon = True
                    t.start()
                    workers.append(t)
                self.q.join()
                for _ in workers:
                    self.q.put(None)
                for t in workers:
                    t.join()
                print(f'\n{MAGENTA}[✓] Scan finished in {int(time.time() - self.start_time)}s. Total IPs: {self.total}{RESET}')
        input('Press Enter to return to main menu...')

    def extract_subdomains(domain):
        console.print(f'[cyan]Extracting subdomains from {domain} using sublist3r...[/cyan]')
        try:
            import sublist3r
            subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            return subdomains
        except Exception as e:
            console.print(f'[red]Error extracting subdomains: {e}[/red]')
            return []
        else:  # inserted
            pass

    def find_hidden_subdomains(domain):
        console.print(f'[cyan]Fetching hidden subdomains from crt.sh for {domain}...[/cyan]')
        url = f'https://crt.sh/?q=%.{domain}&output=json'
        try:
            response = requests.get(url, timeout=10)
            data = response.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    sub = sub.strip()
                    if sub and domain in sub:
                        pass  # postinserted
        except Exception as e:
                    else:  # inserted
                        subdomains.add(sub)
            else:  # inserted
                return list(subdomains)
                console.print(f'[yellow]Warning: Could not fetch hidden subdomains: {e}[/yellow]')
                return []
            else:  # inserted
                pass

    def gather_ip(domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None
        else:  # inserted
            pass

    def save_domains_to_file(domains, filename):
        unique = sorted(set(domains))
        with open(filename, 'w') as f:
            for d in unique:
                f.write(d + '\n')
        console.print(f'[green]Saved {len(unique)} unique domains to \'{filename}\'[/green]')

    def run_subfinder(domain):
        """تشغيل subfinder كأداة خارجية"""  # inserted
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                subs = result.stdout.splitlines()
                return list(set(subs))
            return []
        except Exception as e:
            console.print(f'[red]subfinder error: {e}[/red]')
            return []

    def get_crtsh_subdomains(domain):
        url = f'https://crt.sh/?q=%25.{domain}&output=json'
        try:
            response = requests.get(url, timeout=10)
            data = response.json()
            subs = set()
            for entry in data:
                names = entry.get('name_value', '').split('\n')
                for name in names:
                    if domain in name:
                        subs.add(name.strip())
            return list(subs)
        except Exception as e:
            console.print(f'[yellow]crt.sh warning: {e}[/yellow]')
            return []

    def get_alienvault_subdomains(domain):
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
        subs = []
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get('passive_dns', []):
                    name = record.get('hostname')
                    if name and domain in name:
                        pass  # postinserted
        except Exception as e:
                    else:  # inserted
                        subs.append(name)
            return list(set(subs))
                    console.print(f'[yellow]AlienVault warning: {e}[/yellow]')
                    return []

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
                            pass  # postinserted
        except Exception as e:
                        else:  # inserted
                            subs.append(sub)
            else:  # inserted
                return list(set(subs))
                console.print(f'[yellow]DNSDumpster warning: {e}[/yellow]')
                return []

    def get_virustotal_subdomains(domain, api_key):
        if not api_key:
            return []
        url = f'https://www.virustotal.com/api/v3/domains/{domain}/subdomains'
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
            console.print(f'[yellow]VirusTotal warning: {e}[/yellow]')
            return []

    def extract_subdomains(domain, virustotal_api_key=None):
        console.print(f'[cyan]Extracting subdomains for {domain} from multiple sources...[/cyan]')
        all_subs = []
        all_subs.extend(run_subfinder(domain))
        all_subs.extend(get_crtsh_subdomains(domain))
        all_subs.extend(get_alienvault_subdomains(domain))
        all_subs.extend(get_dnsdumpster_subdomains(domain))
        if virustotal_api_key:
            all_subs.extend(get_virustotal_subdomains(domain, virustotal_api_key))
        unique_subs = list(set(all_subs))
        console.print(f'[green]Found {len(unique_subs)} unique subdomains for {domain}[/green]')
        return unique_subs

    def expand_cidr(cidr):
        return False
        except ValueError as e:
            console.print(f'[bold red]Error: Invalid CIDR format! Could not process range: {cidr}[/bold red]')
            return []

    def check_dns(ip, output_file):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            query = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01'
            sock.sendto(query, (ip, 53))
            response, _ = sock.recvfrom(512)
            if response:
                with open(output_file, 'a') as f:
                    pass  # postinserted
        except Exception:
                    f.write(ip + '\n')
                        console.print(f'[bold green][✔] {ip} | WORKING ---> Saved to {output_file}[/bold green]')
            else:  # inserted
                console.print(f'[bold red][✘] {ip} | NOT WORKING[/bold red]')
        else:  # inserted
            sock.close()
                console.print(f'[bold red][✘] {ip} | NOT WORKING[/bold red]')

    def choose_option():
        console.print('[bold blue]------------------------------------------------------[/bold blue]')
        console.print('[bold yellow]Choose an option:[/bold yellow]')
        console.print('[1] Start scanning with predefined ranges.')
        console.print('[2] Start scanning with a custom range.')
        choice = input('Enter your choice (1 or 2): ')
        return choice

    def get_custom_range_and_file():
        while True:
            cidr = input('Enter the custom range (e.g., 84.235.6.0/24): ')
            if '/' in cidr:
                try:
                    ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                pass  # postinserted
            else:  # inserted
                console.print('[bold red]Error: Invalid format. Please use CIDR format (e.g., 84.235.6.0/24).[/bold red]')
        output_file = input('Enter the name of the output file (e.g., custom_dns.txt): ')
        return (cidr, output_file)
            console.print('[bold red]Error: Invalid CIDR format! Please enter a valid CIDR range.[/bold red]')
        else:  # inserted
            pass

    def scan_dns_process():
        choice = choose_option()
        if choice == '1':
            RANGES = ['10.0.0.0/8']
            output_file = input('Enter the name of the output file (e.g., dns.txt): ')
        else:  # inserted
            if choice == '2':
                RANGES, output_file = get_custom_range_and_file()
            else:  # inserted
                console.print('[bold red]Invalid choice! Exiting...[/bold red]')
                return
        with open(output_file, 'w'):
            pass
        if isinstance(RANGES, str):
            RANGES = [RANGES]
        with ThreadPoolExecutor(max_workers=50) as executor:
            for cidr in RANGES:
                ip_list = expand_cidr(cidr)
                if ip_list:
                    executor.map(lambda ip: check_dns(ip, output_file), ip_list)
                else:  # inserted
                    console.print(f'[bold red]Error: Could not process the CIDR range {cidr}.[/bold red]')
        console.print('[bold blue]------------------------------------------------------[/bold blue]')
        console.print(f'[bold green]Scanning completed successfully! \nWorking IPs saved to: {output_file}[/bold green]')
        console.print('[bold blue]------------------------------------------------------[/bold blue]')
    init(autoreset=True)
    console = Console()

    def slow_print(text, delay=0.03):
        for c in text:
            print(c, end='', flush=True)
            time.sleep(delay)
        print()

    def banner():
        print(Fore.RED + '\n    ☠️☠️☠️ APK CDN HUNTER ☠️☠️☠️\n    🔥 SCANNING APK FILE FOR SECRET DOMAINS 🔥\n    ')
        slow_print(Fore.YELLOW + 'Starting scan... Hold tight, hacker! 🕷️🕷️🕷️\n', 0.05)

    def unzip_apk(apk_path, extract_to):
        if not os.path.exists(apk_path):
            print(Fore.RED + f'[!] Error: APK file \'{apk_path}\' not found!')
            sys.exit(1)
        if os.path.exists(extract_to):
            print(Fore.YELLOW + f'[!] Warning: folder \'{extract_to}\' exists, removing...')
            import shutil
            shutil.rmtree(extract_to)
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print(Fore.GREEN + f'[+] APK extracted to: {extract_to}')

    def read_all_files(folder):
        texts = []
        for root, dirs, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        pass  # postinserted
            except:
                pass
                        texts.append(f.read())
        return texts

    def extract_domains_urls(texts):
        pattern_url = re.compile('https?://[^\\s\"\\\'<>]+')
        pattern_domain = re.compile('(?<=://)?([a-zA-Z0-9.-]+\\.(?:com|net|org|sa|cn|io|co|app|info|biz|online|tech|store))')
        urls = set()
        domains = set()
        for text in texts:
            for url in pattern_url.findall(text):
                urls.add(url.strip())
            for dom in pattern_domain.findall(text):
                domains.add(dom.strip())
        return (urls, domains)

    def extract_keywords(texts):
        keywords = ['cdn', 'api', 'host', 'endpoint', 'payment', 'pay', 'billing', 'checkout', '.alicdn', '.mobily']
        found = set()
        for text in texts:
            for kw in keywords:
                if kw in text.lower():
                    found.add(kw)
        return found

    def get_ip(domain):
        try:
            return socket.gethostbyname(domain)
        except:
            return 'Not resolved'

    def check_cdn(domain):
        cdn_keywords = ['alicdn', 'akamai', 'cloudflare', 'fastly', 'amazon', 'edgekey', 'cdn']
        for kw in cdn_keywords:
            if kw in domain.lower():
                return True
        else:  # inserted
            return False

    def save_results(folder, urls, domains, keywords, cdn_domains, payments):
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, 'urls.txt'), 'w') as f:
            for u in sorted(urls):
                f.write(u + '\n')
        with open(os.path.join(folder, 'domains.txt'), 'w') as f:
            for d in sorted(domains):
                f.write(d + '\n')
        with open(os.path.join(folder, 'keywords.txt'), 'w') as f:
            for k in sorted(keywords):
                f.write(k + '\n')
        with open(os.path.join(folder, 'cdn_domains.txt'), 'w') as f:
            for d in sorted(cdn_domains):
                f.write(d + '\n')
        with open(os.path.join(folder, 'payment_urls.txt'), 'w') as f:
            for p in sorted(payments):
                f.write(p + '\n')

    def extract_payment_urls(urls):
        payment_keys = ['pay', 'payment', 'checkout', 'billing']
        payments = set()
        for url in urls:
            for key in payment_keys:
                if key in url.lower():
                    payments.add(url)
        return payments

    def apk_cdn_hunter():
        banner()
        apk_path = input(Fore.CYAN + '🔍 Enter APK file path: ').strip()
        result_folder = input(Fore.CYAN + '💾 Enter folder name to save results: ').strip()
        slow_print(Fore.MAGENTA + '[*] Extracting APK file ...')
        unzip_apk(apk_path, result_folder + '_extracted')
        slow_print(Fore.MAGENTA + '[*] Reading all files ...')
        texts = read_all_files(result_folder + '_extracted')
        slow_print(Fore.MAGENTA + '[*] Extracting URLs and domains ...')
        urls, domains = extract_domains_urls(texts)
        slow_print(Fore.MAGENTA + '[*] Searching for important keywords ...')
        keywords = extract_keywords(texts)
        slow_print(Fore.MAGENTA + '[*] Extracting payment gateway URLs ...')
        payments = extract_payment_urls(urls)
        slow_print(Fore.MAGENTA + '[*] Analyzing domains and checking for CDN ...')
        cdn_domains = set()
        for d in domains:
            if check_cdn(d):
                cdn_domains.add(d)
        slow_print(Fore.GREEN + '[✔] Saving results ...')
        save_results(result_folder, urls, domains, keywords, cdn_domains, payments)
        print(Fore.YELLOW + f'\n[✔] Scan complete! Results saved in folder: {result_folder}')
        print(Fore.YELLOW + 'Check files:\n - urls.txt\n - domains.txt\n - keywords.txt\n - cdn_domains.txt\n - payment_urls.txt\n')

    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')
    from rich.console import Console
    import time
    import os
    console = Console()
    fpi = '\n              ⢀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣄⣴⣴⣾⣾⣾⣿⣿⣾⣿⣾⣿⣷⣷⣷⣷⣦⣦⣠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⢿⢛⢏⢟⢟⣿⣿⣿⣿⣿⣿⣿⣿⡿⡟⡟⢝⢟⢿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⣿⣏⣔⣴⣰⢄⢌⠘⠽⣿⣿⣿⣿⡿⠏⢃⢡⣠⣢⣢⣌⣻⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣮⡢⣮⣿⣿⣿⣮⢪⣾⣾⣿⣿⣿⣿⣿⣿⣯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⢿⣟⠽⠊⠊⠊⠫⢻⣾⣿⣿⣿⣷⠻⠙⠘⠘⠚⢽⢿⣿⣿⣯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣵⣷⣽⣪⣞⣮⣮⣾⣿⣾⣿⣯⣿⣷⣵⣲⣲⣳⣵⣷⣷⣻⣯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢗⣿⣿⣿⣺⣿⣿⣿⣿⣿⣿⣿⣿⣿⣗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢽⣿⣿⣿⣿⣿⣿⢟⣿⣽⣟⣿⣿⣿⢾⣾⢿⡻⣿⣿⣿⣿⣿⢿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⣷⣕⢭⠹⣾⣾⣿⣿⣏⡻⡽⣟⡟⣏⣿⣿⣿⣾⡾⠍⣕⢧⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣷⣝⢦⡈⠟⠟⠟⠏⠁⣠⣦⡀⠈⠛⠟⠟⠟⢀⡾⣣⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣎⢷⣷⣶⣵⣮⣦⣫⣫⣫⣦⣵⣶⣵⣾⢾⣱⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣯⣷⣿⣿⣿⣿⡛⠛⣻⣿⣿⣿⣿⣟⣵⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⢿⣷⣿⣿⣿⣿⡏⠀⢻⣿⣿⣿⣿⣾⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⡅⠀⣸⣿⣿⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣧⢀⣾⡿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀      ☠⠀MrPYTHON⠀️☠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀Telegram : @Mr_PYT_HON\nHi pro🙋\n\n#------\n[*] Telegram : MrPYTHON🎩✔\\👿\n[*] Telegram : @Mr_PYTHON_YE\\🔝\n[+]Telegram https://t.me/PYT_HON3\\🌍\n'
    B = '                            by: MrPYTHON\n                         Telegram :@Mr_PYTHON_YE \n'
    for char in B:
        if char.isalpha():
            console.print(char, end='', style='bold yellow')
        else:  # inserted
            console.print(char, end='')
        time.sleep(0.04)
os.system('clear')
for char in fpi:
    console.print(char, end='', style='bold yellow')
    time.sleep(0.001)

def print_banner():
    clear_screen()
    console.print(BANNER)

def main_menu():
    print_banner()
    console.print('[bold cyan]Select an option:[/bold cyan]')
    console.print('[green][1][/green] Scan Domain (SNI, SSL, HTTP, HTTPS, Proxy)')
    console.print('[green][2][/green] Extract Subdomains (single domain or from file)')
    console.print('[green][3][/green] Lookup IP addresses from domain list file')
    console.print('[green][4][/green] SCAN CIDR')
    console.print('[green][5][/green] APK CDN Hunter (scan APK for hidden domains)')
    console.print('[green][6][/green] SCAN DNS CIDR')
    console.print('[green][7][/green] Exit')
    choice = console.input('[bold yellow]Enter your choice (1-7): [/bold yellow]').strip()
    return choice

def scan_domain_flow():
    clear_screen()
    console.print(BANNER)
    filename = console.input('[cyan]Enter the domain file path: [/cyan]').strip()
    if not check_file_exists(filename):
        console.print(f'[yellow]File \'{filename}\' not found. Returning...[/yellow]')
        return
    with open(filename, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    if not domains:
        console.print('[yellow]No domains found in the file. Returning...[/yellow]')
        return
    console.print('\n[magenta]Choose scan type:\n1. sni\n2. ssl\n3. proxy\n4. http\n5. https[/magenta]\n')
    scan_choice_map = {'1': 'sni', '2': 'ssl', '3': 'proxy', '4': 'http', '5': 'https'}
    scan_choice = console.input('[cyan]Enter scan type number: [/cyan]').strip()
    while scan_choice not in scan_choice_map:
        scan_choice = console.input('[yellow]Invalid choice. Enter 1-5: [/yellow]').strip()
    scan_type = scan_choice_map[scan_choice]
    while True:
        port_str = console.input('[cyan]Enter port number (e.g. 443): [/cyan]').strip()
        if port_str.isdigit() and 1 <= int(port_str) <= 65535:
            port = int(port_str)
            break
        else:  # inserted
            console.print('[yellow]Invalid port. Enter a number between 1 and 65535.[/yellow]')
    output_file = console.input('[cyan]Enter filename to save successful domains: [/cyan]').strip()
    if not output_file:
        output_file = 'results.txt'
    open(output_file, 'w').close()
    while True:
        workers_str = console.input('[cyan]Enter desired speed [number of workers]: [/cyan]').strip()
        if workers_str.isdigit() and int(workers_str) > 0:
            num_workers = int(workers_str)
            break
        console.print('[yellow]Invalid input. Enter a positive number.[/yellow]')
        continue
    console.print(f'[magenta]\nStarting scan on {len(domains)} domains using {scan_type.upper()} on port {port} with {num_workers} workers...\n[/magenta]')
    scan_func_map = {'sni': scan_sni, 'ssl': scan_ssl, 'proxy': scan_proxy, 'http': scan_http, 'https': scan_https}
    progress = [0]
    start_time = time.time()

    def worker(domain):
        domain = domain.strip()
        success, info = scan_func_map[scan_type](domain, port)
        duration = time.time() - start_time
        with lock:
            progress[0] += 1
            percent = progress[0] / len(domains) * 100
            if success:
                console.print(f'[green]{domain:<30} [{scan_type.upper()}] [PORT: {port}] [{info}] ({duration:.2f}s) ---> {percent:6.2f}%[/green]')
                with open(output_file, 'a') as f:
                    f.write(f'{domain} [{scan_type.upper()}] [PORT: {port}] [{info}]\n')
            else:  # inserted
                console.print(f'[yellow]{domain:<30} [FAIL] {info} ({duration:.2f}s) ---> {percent:6.2f}%[/yellow]')
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        executor.map(worker, domains)

def extract_subdomains_flow():
    console.print('[bold cyan]Subdomain Extraction Flow[/bold cyan]')
    mode = console.input('[bold yellow]Extract from (1) Single domain or (2) Domains from file? Enter 1 or 2: [/bold yellow]').strip()
    virustotal_api_key = None
    if mode == '1':
        domain = console.input('[bold magenta]Enter domain: [/bold magenta]').strip()
        if not domain:
            console.print('[red]Domain cannot be empty.[/red]')
            return
        subs = extract_subdomains(domain, virustotal_api_key)
        filename = console.input('[bold magenta]Enter filename to save subdomains (default: subdomains.txt): [/bold magenta]').strip()
        if not filename:
            filename = 'subdomains.txt'
        save_domains_to_file(subs, filename)
        console.input('[bold yellow]Press Enter to return to main menu...[/bold yellow]')
    else:  # inserted
        if mode == '2':
            filename = console.input('[bold magenta]Enter filename containing domains (one per line): [/bold magenta]').strip()
            if not check_file_exists(filename):
                console.print(f'[red]File \'{filename}\' does not exist.[/red]')
                console.input('[bold yellow]Press Enter to return to main menu...[/bold yellow]')
                return
            with open(filename, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            all_subdomains = []
            for domain in domains:
                console.print(f'[cyan]Extracting subdomains for {domain}...[/cyan]')
                subs = extract_subdomains(domain, virustotal_api_key)
                all_subdomains.extend(subs)
            all_unique = list(set(all_subdomains))
            console.print(f'[green]Total unique subdomains found: {len(all_unique)}[/green]')
            output_file = 'all_subdomains.txt' if not output_file else save_domains_to_file(all_unique, output_file)

def ip_lookup_flow():
    filename = console.input('[bold magenta]Enter filename containing domains to resolve: [/bold magenta]').strip()
    if not check_file_exists(filename):
        console.print(f'[red]File \'{filename}\' does not exist.[/red]')
        console.input('[bold yellow]Press Enter to return to main menu...[/bold yellow]')
        return
    output_file = console.input('[bold magenta]Enter output filename for IPv4 addresses (default: ips.txt): [/bold magenta]').strip()
    if not output_file:
        output_file = 'ips.txt'
    with open(filename, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    resolved_ips = set()
    console.print(f'[cyan]Resolving IPv4 addresses for {len(domains)} domains...[/cyan]')

    def resolve(domain):
        ip = gather_ip(domain)
        with lock:
            if ip:
                resolved_ips.add(ip)
                console.print(f'[green]{domain} -> {ip}[/green]')
            else:  # inserted
                console.print(f'[red]{domain} -> Could not resolve[/red]')
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(resolve, d) for d in domains]
        concurrent.futures.wait(futures)
    with open(output_file, 'w') as f:
        for ip in sorted(resolved_ips):
            f.write(ip + '\n')
    console.print(f'[green]IP lookup completed. Total unique IPv4: {len(resolved_ips)}[/green]')

def main():
    while True:
        choice = main_menu()
        if choice == '1':
            scan_domain_flow()
        else:  # inserted
            if choice == '2':
                extract_subdomains_flow()
            else:  # inserted
                if choice == '3':
                    ip_lookup_flow()
                else:  # inserted
                    if choice == '4':
                        scan_cidr_flow()
                    else:  # inserted
                        if choice == '5':
                            apk_cdn_hunter()
                        else:  # inserted
                            if choice == '6':
                                scan_dns_process()
                            else:  # inserted
                                if choice == '7':
                                    console.print('[bold red]Exiting...[/bold red]')
                                    return
                                console.print('[red]Invalid choice, try again.[/red]')
if __name__ == '__main__':
    try:
        main()
except KeyboardInterrupt:
    print('Please install sublist3r: pip install sublist3r')
    sys.exit(1)
    console.print('\n[bold red]Interrupted by user. Exiting...[/bold red]')