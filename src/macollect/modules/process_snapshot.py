import subprocess
import re
import shlex
from pathlib import Path


class ProcessSnapshot():

    depends_on = []
    inject = {}

    def collect(self) -> dict:
        processes = self._collect_processes()
        flags = self._evaluate_flags(processes)
        return {
            'data': {'processes': processes},
            'flags': flags
            }

    def _evaluate_flags(self, processes: list) -> list:
        flags = []
        known_macos_services = {
            'launchd', 'logd', 'kernelmanagerd', 'syslogd',
            'configd', 'notifyd', 'opendirectoryd', 'securityd'
            }
        for entry in processes:
            initial_flag_count = len(flags)
            if entry['euid'] != entry['ruid']:
                flags.append({
                    'type': 'euid_ruid_mismatch',
                    'source': entry['binary_path'],
                    'detail': f'pid={entry["pid"]} ruid={entry["ruid"]} euid={entry["euid"]}',
                    'reason': 'Process EUID does not match RUID — possible privilege escalation'
                    })
            if entry['process_name'] and entry['comm']:
                comm_name = Path(entry['comm']).name
                process_name = Path(entry['process_name']).name
                if comm_name != process_name:
                    if not entry['binary_path'].startswith(('/usr/', '/System/', '/sbin/', '/bin/')):
                        flags.append({
                            'type': 'argv0_mismatch',
                            'source': entry['binary_path'],
                            'detail': f'pid={entry["pid"]} comm={entry["comm"]} argv0={entry["process_name"]}',
                            'reason': 'Process name does not match argv[0] — possible masquerading'
                        })
            if entry['binary_path'] and entry['binary_path'].startswith(('/tmp', '/var/tmp', '/Users/')):
                flags.append({
                    'type': 'writable_path',
                    'source': entry['binary_path'],
                    'detail': f'pid={entry["pid"]} path={entry["binary_path"]}',
                    'reason': 'Process running from writable location'
                    })
            if entry['process_name'] and entry['process_name'].startswith('.'):
                flags.append({
                    'type': 'hidden_process',
                    'source': entry['binary_path'],
                    'detail': f'pid={entry["pid"]} name={entry["process_name"]}',
                    'reason': 'Process name begins with . — hidden binary'
                    })
            if entry['process_name'] in known_macos_services:
                expected_prefixes = ('/sbin/', '/usr/', '/System/')
                if entry['binary_path'] and not entry['binary_path'].startswith(expected_prefixes):
                    flags.append({
                        'type': 'masquerading',
                        'source': entry['binary_path'],
                        'detail': f'pid={entry["pid"]} name={entry["process_name"]} path={entry["binary_path"]}',
                        'reason': 'Process masquerading as known macOS service from unexpected path'
                        })
            if len(flags) > initial_flag_count:
                responsible_pid = self._get_responsible_pid(entry['pid'])
                change = len(flags) - initial_flag_count
                for i in flags[-change:]:
                    i['responsible_pid'] = responsible_pid
        return flags

    def _get_responsible_pid(self, pid: int) -> int | None:
        try:
            result = subprocess.run(
                ['launchctl', 'procinfo', str(pid)],
                capture_output=True, text=True, timeout=10
                )
            match = re.search(r'responsible pid\s*=\s*(\d+)', result.stdout)
            if match:
                return int(match.group(1))
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    def _collect_processes(self) -> list:
        processes = []
        cmd = ['ps', '-axo', 'pid=,ppid=,pgid=,sess=,ruid=,uid=,lstart=,comm=,args=']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            awk_cmd = [
                'awk',
                'BEGIN{OFS="|"} {lstart=$7" "$8" "$9" "$10" "$11; comm=$12; args=""; for(i=13;i<=NF;i++) args=args (i>13?" ":"") $i; print $1,$2,$3,$4,$5,$6,lstart,comm,args}'
                ]
            awk_result = subprocess.run(
                awk_cmd, input=result.stdout,
                capture_output=True, text=True, timeout=30
                )
            for line in awk_result.stdout.strip().split('\n'):
                if not line:
                    continue
                fields = line.split('|', 8)
                if len(fields) < 9:
                    continue
                try:
                    args_str = fields[8].strip()
                    try:
                        argv = shlex.split(args_str)
                    except ValueError:
                        argv = args_str.split()
                    # NOTE: shlex.split() truncates binary_path at first space for processes
                    # with unquoted spaces in path (e.g. Image Capture, Screen Sharing).
                    # Full fix requires proc_pidpath via ctypes. Tracked: GitHub issue #3
                    binary_path = argv[0] if argv else ''
                    entry = {
                        'pid':              int(fields[0].strip()),
                        'ppid':             int(fields[1].strip()),
                        'pgid':             int(fields[2].strip()),
                        'session_id':       int(fields[3].strip()),
                        'ruid':             int(fields[4].strip()),
                        'euid':             int(fields[5].strip()),
                        'start_time':       fields[6].strip(),
                        'comm':             fields[7].strip(),
                        'cmdline':          args_str,
                        'binary_path':      binary_path,
                        'process_name':     Path(binary_path).name if binary_path else '',
                        'responsible_pid':  None,
                        }
                    processes.append(entry)
                except (ValueError, IndexError):
                    continue
        except subprocess.TimeoutExpired:
            return processes
        return processes