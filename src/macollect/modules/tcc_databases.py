import sqlite3
from pathlib import Path

class TCCDatabases():

    depends_on = []

    def collect(self) -> dict:
        
        tcc = []
        system_db = Path('/Library/Application Support/com.apple.TCC/TCC.db')
        user_dbs = Path('/Users/').glob('*/Library/Application Support/com.apple.TCC/TCC.db')
        if system_db.exists():
            tcc.extend(self._parse_tcc(system_db, scope='system'))
        for path in user_dbs:
            user = path.parts[2]
            tcc.extend(self._parse_tcc(path, scope=user))
        flags = self._evaluate_flags(tcc)
        return {
            'data': {'tcc_entries': tcc},
            'flags': flags
            }

    def _parse_tcc(self, path: Path, scope: str) -> list:
       
        tcc = []
        try:
            conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT service, client, auth_value, last_modified FROM access")
            for row in cursor.fetchall():
                entry = dict(row)
                entry['source'] = str(path)
                entry['scope'] = scope
                tcc.append(entry)
            conn.close()
        except sqlite3.OperationalError as e:
            tcc.append({
                'error': str(e),
                'source': str(path),
                'scope': scope,
                'reason': 'FDA not granted or database inaccessible'
                })
        except Exception:
            pass
        return tcc

    def _evaluate_flags(self, tcc: list) -> list:
       
        flags = []
        sensitive_services = {
            'kTCCServiceSystemPolicyAllFiles',
            'kTCCServiceCamera',
            'kTCCServiceMicrophone',
            'kTCCServiceAddressBook',
            'kTCCServiceCalendar',
            'kTCCServiceScreenCapture',
            'kTCCServiceAccessibility',
            'kTCCServiceLocation',
            'kTCCServiceDeveloperTool',
            }
        for entry in tcc:
            if 'error' in entry:
                continue
            service = entry.get('service')
            client = entry.get('client', '')
            if service in sensitive_services:
                if entry.get('auth_value') == 2:
                    flags.append({
                        'type': 'tcc_sensitive_grant',
                        'source': entry['source'],
                        'detail': f'client={client} service={service} auth_value={entry["auth_value"]} scope={entry["scope"]}',
                        'reason': 'Explicit TCC grant for sensitive service — verify client is expected'
                        })
                if client.startswith('/'):
                    flags.append({
                        'type': 'tcc_path_based_client',
                        'source': entry['source'],
                        'detail': f'client={client} service={service} auth_value={entry["auth_value"]} scope={entry["scope"]}',
                        'reason': 'Path-based TCC client on sensitive service — cannot be revoked by bundle ID, harder to attribute'
                        })
        return flags