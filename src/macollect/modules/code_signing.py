import subprocess
import re
import os


class CodeSigning():

    depends_on = ['persistence', 'processes']
    inject = {
        'persistence_data': ('persistence', 'data'),
        'process_flags':    ('processes', 'flags'),
        }

    def __init__(self, persistence_data: dict = None, process_flags: list = None):
        persistence_data = persistence_data or {}
        process_flags = process_flags or []
        binaries = []
        for entry in persistence_data.get('launch_daemons', []) + persistence_data.get('launch_agents', []):
            if isinstance(entry, dict):
                if entry.get('program'):
                    binaries.append(entry['program'])
                elif entry.get('program_arguments'):
                    binaries.append(entry['program_arguments'][0])
        for entry in process_flags:
            if entry.get('source'):
                binaries.append(entry['source'])
        self.binaries = list(set(binaries))

    def collect(self) -> dict:
        signing = [
            entry for entry in
            (self._check_codesign(b) for b in self.binaries)
            if entry is not None
            ]
        flags = self._evaluate_flags(signing)
        return {
            'data': {'signing': signing},
            'flags': flags
            }

    def _evaluate_flags(self, signing: list) -> list:
        flags = []
        trusted_prefixes = ('/usr/', '/System/', '/sbin/', '/bin/')
        for entry in signing:
            if entry['signing_status'] in ['unsigned', 'adhoc']:
                if entry['signing_status'] == 'unsigned':
                    if entry['path'].startswith(trusted_prefixes):
                        continue
                    reason = 'Unsigned binary'
                else:
                    reason = 'Ad-hoc signed binary in persistence location'
                flags.append({
                    'type': entry['signing_status'],
                    'source': entry['path'],
                    'detail': ', '.join(entry['authority']) if entry['authority'] else '',
                    'reason': reason
                    })
        return flags

    def _check_codesign(self, path: str) -> dict:
        if not os.path.isfile(path):
            return None
        signing = {
            'path': path,
            'identifier': '',
            'format': '',
            'team_id': '',
            'authority': [],
            'codesign_flags': '',
            'notarization_ticket': False,
            'signing_status': '',
            }
        try:
            result = subprocess.run(
                ['codesign', '-dvvv', path],
                capture_output=True, text=True, timeout=10
            )
            output = result.stderr
            signing['signing_status'] = self._derive_signing_status(output)
            id_match = re.search(r'^Identifier=(.+)$', output, re.MULTILINE)
            if id_match:
                signing['identifier'] = id_match.group(1).strip()
            format_match = re.search(r'^Format=(.+)$', output, re.MULTILINE)
            if format_match:
                signing['format'] = format_match.group(1).strip()
            team_match = re.search(r'^TeamIdentifier=(.+)$', output, re.MULTILINE)
            if team_match:
                signing['team_id'] = team_match.group(1).strip()
                if signing['team_id'] == 'not set':
                    signing['team_id'] = ''
            flags_match = re.search(r'flags=(\S+)', output)
            if flags_match:
                signing['codesign_flags'] = flags_match.group(1).strip()
            signing['authority'] = re.findall(r'^Authority=(.+)$', output, re.MULTILINE)
            signing['notarization_ticket'] = 'Notarization Ticket=stapled' in output
        except subprocess.TimeoutExpired:
            signing['signing_status'] = 'timeout'
        except Exception as e:
            signing['signing_status'] = f'error: {e}'
        return signing

    def _derive_signing_status(self, output: str) -> str:
        if 'code object is not signed at all' in output:
            return 'unsigned'
        if 'flags=0x2(adhoc)' in output:
            return 'adhoc'
        if any('Software Signing' in line for line in output.splitlines()):
            return 'apple_platform'
        if any('Developer ID' in line for line in output.splitlines()):
            return 'third_party'
        return 'unknown'