import subprocess
import itertools
from pathlib import Path


class ExtendedAttributes():

    depends_on = ['persistence']
    inject = {
        'persistence_data': ('persistence', 'data'),
        }

    def __init__(self, persistence_data: dict = None):
        self.persistence_data = persistence_data or {}

    def collect(self) -> dict:
        binaries = self._build_binary_list()
        xattr_entries = []
        for path in binaries:
            entry = self._collect_xattrs(path)
            if entry:
                xattr_entries.append(entry)
        flags = self._evaluate_flags(xattr_entries)
        return {
            'data': {'xattr_entries': xattr_entries},
            'flags': flags
            }

    def _build_binary_list(self) -> list:
        binaries = []
        for entry in self.persistence_data.get('launch_daemons', []) + self.persistence_data.get('launch_agents', []):
            if isinstance(entry, dict):
                if entry.get('program'):
                    binaries.append(entry['program'])
                elif entry.get('program_arguments'):
                    binaries.append(entry['program_arguments'][0])
        abused_paths = itertools.chain(
            Path('/tmp').glob('*'),
            Path('/var/tmp').glob('*'),
            Path('/Users/').glob('*/Downloads/*'),
            Path('/Users/').glob('*/Desktop/*'),
            )
        for path in abused_paths:
            if path.is_file():
                binaries.append(str(path))
        return list(set(binaries))

    def _collect_xattrs(self, path: str) -> dict | None:
        try:
            result = subprocess.run(
                ['xattr', '-l', path],
                capture_output=True, text=True, timeout=10
                )
            if not result.stdout.strip():
                return None
            entry = {
                'source': path,
                'quarantine': '',
                'where_froms': [],
                'other': []
                }
            lines = result.stdout.splitlines()
            for i, line in enumerate(lines):
                if 'com.apple.quarantine' in line and ':' in line:
                    entry['quarantine'] = line.split(':', 1)[-1].strip()
                elif 'kMDItemWhereFroms' in line:
                    where_result = subprocess.run(
                        ['xattr', '-p', 'com.apple.metadata.kMDItemWhereFroms', path],
                        capture_output=True, text=True, timeout=10
                    )
                    entry['where_froms'] = where_result.stdout.strip()
                elif line and not line.startswith(' ') and ':' in line:
                    attr_name = line.split(':')[0].strip()
                    if attr_name not in (
                        'com.apple.quarantine',
                        'com.apple.metadata.kMDItemWhereFroms'
                        ):
                        entry['other'].append(attr_name)
            return entry
        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    def _evaluate_flags(self, xattr_entries: list) -> list:
        flags = []
        for entry in xattr_entries:
            if entry.get('where_froms'):
                flags.append({
                    'type': 'downloaded_binary',
                    'source': entry['source'],
                    'detail': f'where_froms={entry["where_froms"]}',
                    'reason': 'Binary in persistence or abused path has download provenance — verify source URL'
                    })
            if entry.get('quarantine'):
                flags.append({
                    'type': 'quarantined_binary',
                    'source': entry['source'],
                    'detail': f'quarantine={entry["quarantine"]}',
                    'reason': 'Binary carries quarantine attribute — records originating application and download timestamp'
                    })
        return flags