import subprocess
import os
from socket import gethostname
import re

class SystemBaseline():

    depends_on = []
    inject = {}

    def collect(self) -> dict:
        baseline = {}
        baseline['hostname'] = gethostname()
        baseline['uid'] = os.getuid()
        baseline['euid'] = os.geteuid()
        try:
            who = subprocess.run(['who'], capture_output=True, text=True, timeout=10)
            current_users = []
            for line in who.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                field = line.split()
                current_users.append({
                    'username': field[0],
                    'line': field[1],
                    'login_time': " ".join(field[2:5])
                })
            baseline['current_users'] = current_users
        except subprocess.TimeoutExpired:
            baseline['current_users'] = []
        try:
            uptime = subprocess.run(['uptime'],
                capture_output=True, text=True, timeout=10)
            match = re.search(r'up (.+?), \d+ user', uptime.stdout)
            baseline['uptime'] = match.group(1).strip() if match else ''
        except subprocess.TimeoutExpired:
            baseline['uptime'] = ''
        try:
            baseline['macos_version'] = subprocess.run(['sw_vers', '-productVersion'],
                capture_output=True, text=True, timeout=10).stdout.strip()
        except subprocess.TimeoutExpired:
            baseline['macos_version'] = ''
        try:
            baseline['build_version'] = subprocess.run(['sw_vers', '-buildVersion'],
                capture_output=True, text=True, timeout=10).stdout.strip()
        except subprocess.TimeoutExpired:
            baseline['build_version'] = ''
        try:
            baseline['architecture'] = subprocess.run(['uname', '-m'],
                capture_output=True, text=True, timeout=10).stdout.strip()
        except subprocess.TimeoutExpired:
            baseline['architecture'] = ''
        try:
            baseline['hardware_model'] = subprocess.run(['sysctl', '-n', 'hw.model'],
                capture_output=True, text=True, timeout=10).stdout.strip()
        except subprocess.TimeoutExpired:
            baseline['hardware_model'] = ''
        try:
            output = subprocess.run(['csrutil', 'status'],
                capture_output=True, text=True, timeout=10).stdout.strip()
            baseline['sip_status'] = 'enabled' if 'enabled' in output \
            else 'disabled' if 'disabled' in output else 'unknown'
        except subprocess.TimeoutExpired:
            baseline['sip_status'] = ''
        return {
            'data': baseline,
            'flags': []
        }

