from flask import Flask, request, render_template_string, jsonify
import subprocess
import nmap
import requests
import json
from bs4 import BeautifulSoup

app = Flask(__name__)

# NVD API URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Define functions
def check_cves_via_nvd_api(tech_name):
    params = {
        'keyword': tech_name,
        'resultsPerPage': 5
    }
    try:
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            cves = []
            if 'vulnerabilities' in data and data['vulnerabilities']:
                for item in data['vulnerabilities']:
                    cve = item.get('cve', {}).get('id')
                    description = item.get('cve', {}).get('descriptions', [{}])[0].get('value')
                    cves.append({'cve_id': cve, 'description': description})
                return cves
            else:
                return None
        else:
            return None
    except Exception as e:
        return None

def detect_basic_technologies(domain):
    tech_info = []
    try:
        response = requests.get(f'http://{domain}', timeout=10)
        if 'x-powered-by' in response.headers:
            tech_info.append(response.headers['x-powered-by'])
        if 'server' in response.headers:
            tech_info.append(response.headers['server'])
        soup = BeautifulSoup(response.content, 'html.parser')
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator:
            tech_info.append(meta_generator.get('content'))
    except Exception as e:
        return tech_info
    return tech_info

def find_subdomains(domain):
    try:
        response = requests.get(f'https://crt.sh/?q=%25.{domain}&output=json')
        if response.status_code == 200:
            json_data = response.json()
            subdomains = set([item['name_value'] for item in json_data])
            return list(subdomains)
        else:
            return []
    except Exception as e:
        return []

def nmap_scan(domain):
    nm = nmap.PortScanner()
    scan_info = {}
    try:
        scan_result = nm.scan(domain, '1-1000', '-sV')
        if scan_result:
            for host in nm.all_hosts():
                scan_info['host'] = host
                scan_info['hostname'] = nm[host].hostname()
                scan_info['state'] = nm[host].state()
                protocols = {}
                for protocol in nm[host].all_protocols():
                    ports = {}
                    for port in nm[host][protocol].keys():
                        ports[port] = {
                            'state': nm[host][protocol][port]['state'],
                            'service': nm[host][protocol][port]['name']
                        }
                    protocols[protocol] = ports
                scan_info['protocols'] = protocols
            return scan_info
        else:
            return {}
    except Exception as e:
        return {}

def run_dirsearch(domain):
    dirsearch_results = []
    try:
        dirsearch_cmd = f"dirsearch -u http://{domain} -e php,html,js,txt"
        process = subprocess.Popen(dirsearch_cmd, shell=True, stdout=subprocess.PIPE)
        for line in process.stdout:
            decoded_line = line.decode('utf-8').strip()
            if "200" in decoded_line or "301" in decoded_line:
                dirsearch_results.append(decoded_line)
        return dirsearch_results
    except Exception as e:
        return []

def find_login_pages(domain):
    login_pages_found = []
    login_paths = [
        "/login", "/admin", "/administrator", "/user/login", "/wp-login.php", "/wp-admin", "/signin", "/account/login"
    ]
    for path in login_paths:
        url = f"http://{domain}{path}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                login_pages_found.append(url)
        except requests.ConnectionError:
            pass
        except Exception as e:
            pass
    return login_pages_found

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        result = {
            'domain': domain,
            'subdomains': [],
            'nmap_scan': {},
            'technologies': [],
            'dirsearch': [],
            'login_pages': [],
            'cves': {}
        }

        # 1. Detect basic technologies and check CVEs first
        tech_info = detect_basic_technologies(domain)
        result['technologies'] = tech_info

        if tech_info:
            for tech in tech_info:
                cves = check_cves_via_nvd_api(tech)
                if cves:
                    result['cves'][tech] = cves

        # 2. Find subdomains
        subdomains = find_subdomains(domain)
        if subdomains:
            result['subdomains'] = subdomains

        # 3. Run Nmap scan on the domain
        nmap_info = nmap_scan(domain)
        result['nmap_scan'] = nmap_info

        # 4. Run directory brute-forcing using Dirsearch
        dirsearch_results = run_dirsearch(domain)
        result['dirsearch'] = dirsearch_results

        # 5. Find potential login pages
        login_pages = find_login_pages(domain)
        result['login_pages'] = login_pages

        return render_template_string("""<html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 20px; }
                    h1 { color: #0056b3; text-align: center; font-size: 36px; margin-bottom: 20px; }
                    h2 { color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 10px; margin-bottom: 10px; }
                    pre { background-color: #333; color: #fff; padding: 10px; border-radius: 5px; overflow-x: auto; }
                    ul { list-style-type: none; padding: 0; }
                    ul li { background-color: #fff; margin: 5px 0; padding: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1); }
                    a { color: #007bff; text-decoration: none; }
                    a:hover { text-decoration: underline; }
                    .header { text-align: center; margin-bottom: 30px; }
                    .header h1 { font-size: 48px; color: #ff5722; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>SecureSpectra-X</h1>
                </div>
                <h1>Security Check Results for {{ result.domain }}</h1>
                <h2>Technologies Detected</h2>
                <ul>
                    {% for tech in result.technologies %}
                    <li>{{ tech }}</li>
                    {% endfor %}
                </ul>
                <h2>CVEs Detected</h2>
                <ul>
                    {% for tech, cves in result.cves.items() %}
                    <li>{{ tech }}
                        <ul>
                            {% for cve in cves %}
                            <li><strong>{{ cve.cve_id }}</strong>: {{ cve.description }}</li>
                            {% endfor %}
                        </ul>
                    </li>
                    {% endfor %}
                </ul>
                <h2>Subdomains</h2>
                <ul>
                    {% for subdomain in result.subdomains %}
                    <li>{{ subdomain }}</li>
                    {% endfor %}
                </ul>
                <h2>Nmap Scan Results</h2>
                <pre>{{ result.nmap_scan | tojson(indent=4) }}</pre>
                <h2>Directory Brute-Forcing Results</h2>
                <ul>
                    {% for result in result.dirsearch %}
                    <li>{{ result }}</li>
                    {% endfor %}
                </ul>
                <h2>Login Pages</h2>
                <ul>
                    {% for page in result.login_pages %}
                    <li><a href="{{ page }}" target="_blank">{{ page }}</a></li>
                    {% endfor %}
                </ul>
                <a href="/">Back</a>
            </body>
            </html>""", result=result)

    return '''
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 20px; }
                h1 { color: #0056b3; text-align: center; font-size: 36px; margin-bottom: 20px; }
                form { text-align: center; }
                input[type="text"] { padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 5px; }
                button { padding: 10px 20px; font-size: 16px; border: none; border-radius: 5px; background-color: #007bff; color: #fff; cursor: pointer; }
                button:hover { background-color: #0056b3; }
            </style>
        </head>
        <body>
            <h1>SecureSpectra-X</h1>
            <form method="post">
                <label for="domain">Enter the domain:</label>
                <input type="text" id="domain" name="domain" required>
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
    '''

if __name__ == "__main__":
    app.run(debug=True)
