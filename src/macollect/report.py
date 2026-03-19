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
        process_data = results.get('processes', {}).get('data', {})
        signing_data = results.get('signing', {}).get('data', {})
        tcc_data = results.get('tcc', {}).get('data', {})
        xattr_data = results.get('xattr', {}).get('data', {})
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
                'flags': []
            },
            'process_snapshot': {
                'data': process_data,
                'flags': []
            },
            'code_signing': {
                'data': signing_data,
                'flags': []
            },
            'tcc_databases': {
                'data': tcc_data,
                'flags': []
            },
            'extended_attributes': {
                'data': xattr_data,
                'flags': []
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