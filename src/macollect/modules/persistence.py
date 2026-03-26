import subprocess
import plistlib
from pathlib import Path
import itertools


class Persistence():
    
    def collect(self) -> dict:
        persistence = {}
        persistence['btm'] = self._collect_btm() or ''
        persistence['launch_daemons'] = self._collect_launch_daemons() or []
        persistence['launch_agents'] = self._collect_launch_agents() or []
        persistence['login_items'] = self._collect_login_items() or []
        persistence['loginwindow'] = self._collect_loginwindow() or {}
        persistence['shell_configs'] = self._collect_shell_configs() or {}
        persistence['sudoers'] = self._collect_sudoers() or {}
        persistence['cron'] = self._collect_cron() or {}
        flags = self._evaluate_flag(persistence)
        return {
            'data': persistence,
            'flags': flags
            }
    
    def _evaluate_flag(self, persistence: dict) -> list:
        flags = []
        for entry in persistence['launch_daemons'] + persistence['launch_agents']:
            if entry['program'] and entry['program'].startswith(('/tmp', '/var/tmp', '/Users/')):
                flags.append({
                    'type': 'writable_path',
                    'source': entry['source'],
                    'detail': entry['program'],
                    'reason': 'Persistence method runs from a writable location'
                })
            if entry['program'] and entry['program'].startswith('.'):
                flags.append({
                    'type' : 'hidden_file',
                    'source': entry['source'],
                    'detail': entry['program'],
                    'reason': 'Program key pointing to hidden file'
                })
            for arg in entry['program_arguments']:
                if arg.startswith(('/tmp', '/var/tmp', '/Users/')):
                    flags.append({
                        'type' : 'writable_path',
                        'source' : entry['source'],
                        'detail' : arg,
                        'reason' : 'Persistence method runs from a writable location',
                    })
            if not entry['label']:
                flags.append({
                    'type' : 'empty_label',
                    'source' : entry['source'],
                    'reason' :  'Missing or empty label field in plist'
                })
        for source, content in persistence['sudoers'].items():
            for line in content.split('\n'):
                if 'NOPASSWD' in line and not line.strip().startswith('#'):
                    flags.append({
                        'type' : 'sudoers_unexpected_entry',
                        'source' : source,
                        'detail' : line,
                        'reason' : 'NOPASSWD entry in sudoers'
                    })
        if persistence['loginwindow'].get('auto_login_user'):
            flags.append({
                'type': 'autologin_enabled',
                'source': '/Library/Preferences/com.apple.loginwindow.plist',
                'detail': persistence['loginwindow']['auto_login_user'],
                'reason': 'Autologin is enabled'
            })
        return flags
        
    def _collect_btm(self) -> str:
        try:
            btm = subprocess.run(['sfltool', 'dumpbtm'], 
                capture_output=True, text=True, timeout=10).stdout.strip()
        except subprocess.TimeoutExpired:
            btm = ''
        return btm

    def _collect_launch_daemons(self) -> list:
        launch_daemons = []
        paths = itertools.chain(
            Path('/Library/LaunchDaemons/').glob('*.plist'),
            Path('/System/Library/LaunchDaemons/').glob('*.plist'),
            Path('/Applications/').glob('*.app/Contents/Library/LaunchDaemons/*.plist')
        )
        for path in paths:
            entry = {}
            try:
                with open(path, 'rb') as f:
                    content = plistlib.load(f)
                    entry['source'] = str(path)
                    entry['label'] = content.get('Label', '')
                    entry['program'] = content.get('Program', '')
                    entry['program_arguments'] = content.get('ProgramArguments', [])
                    entry['run_at_load'] = content.get('RunAtLoad', False)
                    entry['keep_alive'] = content.get('KeepAlive', False)
                    entry['username'] = content.get('UserName', '')
                    entry['disabled'] = content.get('Disabled', False)
                    entry['environment_variables'] = content.get('EnvironmentVariables', {})
                    # Skip configuration-only plists (no Label or Program — e.g. jetsam memory config)
                    if not entry['label'] and not entry['program'] and not entry['program_arguments']:
                        continue
                    launch_daemons.append(entry)
            except PermissionError:
                launch_daemons.append(f'PermissionError for {path}')
                continue
            except Exception:
                continue
        return launch_daemons

    def _collect_launch_agents(self) -> list:
        launch_agents = []
        paths = itertools.chain(
            Path('/Library/LaunchAgents/').glob('*.plist'),
            Path('/Users/').glob('*/Library/LaunchAgents/*.plist'),
            Path('/System/Library/LaunchAgents/').glob('*.plist'),
        )
        for path in paths:
            entry = {}
            if path.parts[1] == 'Users':
                user = path.parts[2]
            else:
                user = ''
            try:
                with open(path, 'rb') as f:
                    content = plistlib.load(f)
                    entry['source'] = str(path)
                    entry['label'] = content.get('Label', '')
                    entry['program'] = content.get('Program', '')
                    entry['program_arguments'] = content.get('ProgramArguments', [])
                    entry['run_at_load'] = content.get('RunAtLoad', False)
                    entry['keep_alive'] = content.get('KeepAlive', False)
                    entry['username'] = user
                    entry['disabled'] = content.get('Disabled', False)
                    entry['environment_variables'] = content.get('EnvironmentVariables', {})
                    # Skip configuration-only plists (no Label or Program — e.g. jetsam memory config)
                    if not entry['label'] and not entry['program'] and not entry['program_arguments']:
                        continue
                    launch_agents.append(entry)
            except PermissionError:
                launch_agents.append(f'PermissionError for {path}')
                continue
            except Exception:
                continue
        return launch_agents

    def _collect_login_items(self) -> list:
        login_items = []
        paths = Path('/Applications/').glob('*.app/Contents/Library/LoginItems/*')
        for path in paths:
            login_items.append(str(path))
        return login_items
    
    def _collect_loginwindow(self) -> dict:
        login_window = {}
        source = '/Library/Preferences/com.apple.loginwindow.plist'
        login_window['source'] = source
        try:
            with open(source, 'rb') as f:
                content = plistlib.load(f)
                login_window['auto_login_user'] = content.get('autoLoginUser', None)
                login_window['guest_enabled'] = content.get('GuestEnabled', False)
                login_window['last_username'] = content.get('lastUserName', '')
        except PermissionError:
            login_window['error'] = f'PermissionError for {source}'
        except Exception as e:
            login_window['error'] = f'Error: {e}, for {source}'
        return login_window
    
    def _collect_shell_configs(self) -> dict:
        shell_configs = {}
        users = Path('/Users/').glob('*/')
        shells = ['.zshrc', '.zprofile', '.zlogin', '.zlogout', '.bashrc', '.bash_profile']
        system_configs = [Path('/etc/zshrc'), Path('/etc/zprofile'), Path('/etc/profile')]
        for user in users:
            for shell in shells:
                path = user / shell
                if path.exists():
                    entry, content = self._read_text_file(path)
                    shell_configs[entry] = content
        for path in system_configs:
            if path.exists():
                entry, content = self._read_text_file(path)
                shell_configs[entry] = content                  
        return shell_configs

    def _collect_sudoers(self) -> dict:
        collect_sudoers = {}
        paths = itertools.chain(
            [Path('/etc/sudoers')],
            Path('/private/etc/sudoers.d/').glob('*')
        )
        for path in paths:
            if path.exists():
                entry, content = self._read_text_file(path)
                collect_sudoers[entry] = content
        return collect_sudoers


    def _collect_cron(self) -> dict:
        collect_cron = {}
        paths = itertools.chain(
            [Path('/etc/crontab')],
            Path('/var/at/tabs/').glob('*'),
            Path('/usr/lib/cron/tabs').glob('*')
        )
        for path in paths:
            if path.exists():
                entry, content = self._read_text_file(path)
                collect_cron[entry] = content
        try:
            atq = subprocess.run(['atq'], 
                capture_output=True, text=True, timeout=10).stdout.strip()
        except subprocess.TimeoutExpired:
            atq = ''
        collect_cron['atq'] = atq
        return collect_cron
    
    def _read_text_file(self, path: Path) -> dict:
        try:
            with open(path, 'r') as f:
                content = f.read()
                return str(path), content
        except PermissionError:
            return str(path), f'PermissionError for {path}'
        except Exception as e:
            return str(path), f'Error: {e}, for {path}' 