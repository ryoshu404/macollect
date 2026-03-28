from macollect.report import ReportBuilder
from macollect.modules.system_baseline import SystemBaseline
from macollect.modules.persistence import Persistence
from macollect.modules.process_snapshot import ProcessSnapshot
from macollect.modules.code_signing import CodeSigning
from macollect.modules.tcc_databases import TCCDatabases

class MacollectPipeline:
    
    def __init__(self, modules: list, time_window: int = 24):
        
        self.registry = {
            'baseline': SystemBaseline,
            'persistence': Persistence,
             'processes': ProcessSnapshot,
             'signing': CodeSigning,
             'tcc': TCCDatabases,
            # 'xattr': ExtendedAttributes,
            # 'credentials': CredentialArtifacts,
            # 'logs': UnifiedLog
        }
        self.modules = modules
        self.time_window = time_window

    def run(self) -> dict:
        errors = []
        results = {}
        if not self.modules:
            self.modules = ['baseline', 'persistence', 'processes', 'signing', 'tcc',]
                #'xattr', 'credentials','logs']
        modules_to_run = self._resolve_modules(self.modules)
        for name in modules_to_run:
            module_class = self.registry[name]
            if name == 'signing':
                binaries = []
                persistence_data = results.get('persistence', {}).get('data', {})
                process_flags = results.get('processes', {}).get('flags', [])
                for entry in persistence_data.get('launch_daemons', []) + persistence_data.get('launch_agents', []):
                    if entry.get('program'):
                        binaries.append(entry['program'])
                    elif entry.get('program_arguments'):
                        binaries.append(entry['program_arguments'][0])
                for entry in process_flags:
                    binaries.append(entry['source'])
                binaries = list(set(binaries))
                module = module_class(binaries=binaries)
            else:    
                module = module_class()
            try:
                results[name] = module.collect()
            except Exception as e:
                results[name] = {'data': {}, 'flags': []}
                errors.append(f'{name}: {str(e)}')
        results['errors'] = errors
        report_builder = ReportBuilder()
        report = report_builder.build(results)
        return report
    
    def _resolve_modules(self, modules: list) -> list:
        modules_to_run = []
        for m in modules:
            m_class = self.registry[m]
            for dependency in m_class.depends_on:
                if dependency not in modules_to_run:
                    modules_to_run.append(dependency)
            if m not in modules_to_run:
                modules_to_run.append(m)
        return modules_to_run

