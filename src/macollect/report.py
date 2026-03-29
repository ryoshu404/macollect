from datetime import datetime
import os
import importlib.metadata

try:
    VERSION = importlib.metadata.version('macollect')
except importlib.metadata.PackageNotFoundError:
    VERSION = 'unknown'

class ReportBuilder:
    
    def build(self, results: dict) -> dict:

        report = {}
        baseline_data = results.get('baseline', {}).get('data', {})
        persistence_data = results.get('persistence', {}).get('data', {})
        persistence_flags = results.get('persistence', {}).get('flags', [])
        process_data = results.get('processes', {}).get('data', {})
        process_flags = results.get('processes', {}).get('flags', [])
        signing_data = results.get('signing', {}).get('data', {})
        signing_flags = results.get('signing', {}).get('flags', [])
        tcc_data = results.get('tcc', {}).get('data', {})
        tcc_flags = results.get('tcc', {}).get('flags', [])
        xattr_data = results.get('xattr', {}).get('data', {})
        xattr_flags = results.get('xattr', {}).get('flags', [])
        credentials_data = results.get('credentials', {}).get('data', {})
        logs_data = results.get('logs', {}).get('data', {})
        report['collection_metadata'] = {
            'macollect_version': VERSION,
            'collected_at': datetime.now().isoformat(),
            'collected_by': os.getenv('SUDO_USER'),
            'hostname': baseline_data.get('hostname', ''),
            'macos_version': baseline_data.get('macos_version', ''),
            'architecture': baseline_data.get('architecture', '')
        }
        report['modules'] = {
            'system_baseline': {
                'data': baseline_data,
                'flags': []
            },
            'persistence': {
                'data': persistence_data,
                'flags': persistence_flags
            },
            'process_snapshot': {
                'data': process_data,
                'flags': process_flags
            },
            'code_signing': {
                'data': signing_data,
                'flags': signing_flags
            },
            'tcc_databases': {
                'data': tcc_data,
                'flags': tcc_flags
            },
            'extended_attributes': {
                'data': xattr_data,
                'flags': xattr_flags
            },
            'credential_artifacts': {
                'data': credentials_data,
                'flags': []
            },
            'unified_log': {
                'data': logs_data,
                'flags': []
            }
        }
        report['errors'] = []

        return report