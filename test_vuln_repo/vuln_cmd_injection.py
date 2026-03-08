# vuln_cmd_injection.py - Command Injection vulnerabilities
import os
import subprocess
from flask import request, Flask

app = Flask(__name__)

def ping_host(hostname):
    """Vulnerable: Command injection via os.system"""
    # BAD: Direct string concatenation with user input
    os.system("ping -c 1 " + hostname)
    
def check_server(server_name):
    """Vulnerable: Command injection via subprocess.call"""
    # BAD: Shell=True with user input
    subprocess.call(f"nslookup {server_name}", shell=True)

@app.route('/exec')
def exec_command():
    """Vulnerable endpoint with command injection"""
    cmd = request.args.get('cmd', '')
    # BAD: Direct execution of user input
    os.system(cmd)
    return "Command executed"

@app.route('/ping')
def ping():
    """Vulnerable ping endpoint"""
    host = request.args.get('host', 'localhost')
    ping_host(host)
    return f"Pinged {host}"

if __name__ == '__main__':
    app.run(debug=True)
