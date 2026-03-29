from pathlib import Path


class CredentialArtifacts():

    depends_on = []
    inject = {}

    def collect(self) -> dict:
        data = {}
        data['shell_history'] = self._collect_shell_history()
        data['ssh'] = self._collect_ssh()
        data['credential_exposure'] = self._collect_credential_exposure()
        data['keychain_metadata'] = self._collect_keychain_metadata()
        flags = self._evaluate_flags(data)
        return {
            'data': data,
            'flags': flags
            }

    def _evaluate_flags(self, data: dict) -> list:
        flags = []
        if data['credential_exposure'].get('kcpassword_present'):
            flags.append({
                'type': 'kcpassword_present',
                'source': '/etc/kcpassword',
                'detail': '',
                'reason': 'kcpassword present — autologin credential file exists on disk in obfuscated plaintext'
                })
        if data['credential_exposure'].get('vnc_settings_present'):
            flags.append({
                'type': 'vnc_settings_present',
                'source': '/Library/Preferences/com.apple.VNCSettings.txt',
                'detail': '',
                'reason': 'VNC settings file present — may contain obfuscated VNC password'
                })
        for user, artifacts in data['ssh'].items():
            if artifacts.get('authorized_keys'):
                flags.append({
                    'type': 'authorized_keys_present',
                    'source': f'/Users/{user}/.ssh/authorized_keys',
                    'detail': '',
                    'reason': 'authorized_keys file present — unexpected entries are a persistence mechanism'
                    })
        for path, meta in data['keychain_metadata'].items():
            if meta.get('permissions') and meta['permissions'] in ('0o777', '0o666'):
                flags.append({
                    'type': 'keychain_unexpected_permissions',
                    'source': path,
                    'detail': f'permissions={meta["permissions"]}',
                    'reason': 'Keychain file has unexpected permissions — possible misconfiguration or tampering'
                    })
        return flags

    def _collect_shell_history(self) -> dict:
        history = {}
        users = Path('/Users/').glob('*/')
        for user in users:
            user_history = {}
            for fname in ('.zsh_history', '.bash_history'):
                path = user / fname
                if path.exists():
                    _, content = self._read_text_file(path)
                    user_history[fname] = content
            if user_history:
                history[user.name] = user_history
        return history

    def _collect_ssh(self) -> dict:
        ssh = {}
        users = Path('/Users/').glob('*/')
        for user in users:
            ssh_dir = user / '.ssh'
            if not ssh_dir.exists():
                continue
            user_ssh = {}
            for fname in ('known_hosts', 'authorized_keys', 'config'):
                path = ssh_dir / fname
                if path.exists():
                    _, content = self._read_text_file(path)
                    user_ssh[fname] = content
            if user_ssh:
                ssh[user.name] = user_ssh
        return ssh

    def _collect_credential_exposure(self) -> dict:
        exposure = {}
        exposure['kcpassword_present'] = Path('/etc/kcpassword').exists()
        exposure['vnc_settings_present'] = Path('/Library/Preferences/com.apple.VNCSettings.txt').exists()
        return exposure

    def _collect_keychain_metadata(self) -> dict:
        keychains = {}
        paths = []
        paths.append(Path('/Library/Keychains/System.keychain'))
        for p in Path('/Users/').glob('*/Library/Keychains/login.keychain-db'):
            paths.append(p)
        for path in paths:
            if path.exists():
                try:
                    stat = path.stat()
                    keychains[str(path)] = {
                        'permissions': oct(stat.st_mode & 0o777),
                        'modified': stat.st_mtime,
                        'size_bytes': stat.st_size
                        }
                except Exception:
                    keychains[str(path)] = {'error': 'stat failed'}
        return keychains

    # identical to persistence._read_text_file, intentional, no shared utils module
    def _read_text_file(self, path: Path) -> tuple:
        try:
            with open(path, 'r') as f:
                return str(path), f.read()
        except PermissionError:
            return str(path), f'PermissionError for {path}'
        except Exception as e:
            return str(path), f'Error: {e}, for {path}'