from flask import Flask, request, render_template, jsonify, Response
import nmap
import requests
import concurrent.futures
import threading
import socket
import time

app = Flask(__name__)
IPAPI_API_KEY = '0ace3c0c7c3531' 

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    targets = request.form.get('targets')
    domain_name = request.form.get('domain')
    port_range = request.form.get('portRange')
    scan_type = request.form.get('scanType')

    try:
        ip_address = socket.gethostbyname(domain_name)
    except socket.gaierror:
        return jsonify({'error': 'Invalid domain name'})

    targets_list = targets.split(",")
    scan_results = multi_threaded_scan([ip_address] + targets_list, port_range, scan_type)

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(scan_target, target, port_range, scan_type): target for target in [ip_address] + targets_list}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            open_ports, geolocation_data = future.result()

            result = {
                'target': target,
                'open_ports': open_ports
            }

            result['geolocation'] = {
                'ip_address': geolocation_data.get('ip', 'Unknown'),
                'location': f"{geolocation_data.get('city', 'Unknown')}, {geolocation_data.get('region_name', 'Unknown')}, {geolocation_data.get('country_name', 'Unknown')}"
            }

            results.append(result)

    return jsonify(results)

def scan_target(target, port_range, scan_type):
    open_ports = perform_scan(target, port_range, scan_type)
    geolocation_data = get_geolocation(target)
    return open_ports, geolocation_data

def multi_threaded_scan(targets, port_range, scan_type):
    results = []
    threads = []

    for target in targets:
        thread = threading.Thread(target=lambda: results.append((target, perform_scan(target, port_range, scan_type))))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return results

def perform_scan(target, port_range, scan_type):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=f"-p {port_range} {scan_type}")  
    
    open_ports = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                state = nm[host][proto][port]['state']
                if state == 'open':
                    service_info = nm[host][proto][port].get('service', {}) 
                    open_ports.append((port, service_info))

    return open_ports

def get_geolocation(ip_address):
    response = requests.get(f"https://ipinfo.io/{ip_address}/json?token=0ace3c0c7c3531")
    data = response.json()
    return data

@app.route('/scan-updates')
def scan_updates():
    def generate_updates():
        yield "Scanning target 1...\n"
        time.sleep(2)
        yield "Scanning target 2...\n"
        time.sleep(2)
        yield "Scanning target 3...\n"
        time.sleep(2)
        yield "Scan complete."

    return Response(generate_updates(), content_type='text/event-stream')

if __name__ == "__main__":
            app.run(debug=True)
