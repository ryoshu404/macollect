from macollect.report import ReportBuilder
from macollect.modules.system_baseline import SystemBaseline
from macollect.modules.persistence import Persistence
from macollect.modules.process_snapshot import ProcessSnapshot
from macollect.modules.code_signing import CodeSigning
from macollect.modules.tcc_databases import TCCDatabases
from macollect.modules.extended_attributes import ExtendedAttributes
from macollect.modules.credential_artifacts import CredentialArtifacts
from macollect.modules.unified_log import UnifiedLog


class MacollectPipeline:

    def __init__(self, modules: list, time_window: int = 24):
        self.registry = {
            'baseline':    SystemBaseline,
            'persistence': Persistence,
            'processes':   ProcessSnapshot,
            'signing':     CodeSigning,
            'tcc':         TCCDatabases,
            'xattr':       ExtendedAttributes,
            'credentials': CredentialArtifacts,
             'logs':        UnifiedLog
            }
        self.modules = modules
        self.time_window = time_window

    def run(self) -> dict:
        errors = []
        results = {}
        if not self.modules:
            self.modules = ['baseline', 'persistence', 'processes', 'signing', 'tcc', 'xattr',
                            'credentials', 'logs']
        modules_to_run = self._resolve_modules(self.modules)
        for name in modules_to_run:
            module_class = self.registry[name]
            kwargs = self._build_kwargs(module_class, results)
            if name == 'logs':
                kwargs['time_window'] = self.time_window
            module = module_class(**kwargs)
            try:
                results[name] = module.collect()
            except Exception as e:
                results[name] = {'data': {}, 'flags': []}
                errors.append(f'{name}: {str(e)}')
        results['errors'] = errors
        report_builder = ReportBuilder()
        report = report_builder.build(results)
        return report

    def _build_kwargs(self, module_class, results: dict) -> dict:
        kwargs = {}
        for param, (module_name, key) in getattr(module_class, 'inject', {}).items():
            kwargs[param] = results.get(module_name, {}).get(key, {})
        return kwargs

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