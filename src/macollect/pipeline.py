from macollect.report import ReportBuilder
from macollect.modules.system_baseline import SystemBaseline

class MacollectPipeline:
    
    def __init__(self, modules: list, time_window: int = 24):
        
        self.registry = {
            'baseline': SystemBaseline,
            # 'persistence': Persistence,
            # 'processes': ProcessSnapshot,
            # 'signing': CodeSigning,
            # 'tcc': TCCDatabases,
            # 'xattr': ExtendedAttributes,
            # 'credentials': CredentialArtifacts,
            # 'logs': UnifiedLog
        }
        self.modules = modules
        self.time_window = time_window

    def run(self, VERSION) -> dict:
        results = {}
        if not self.modules:
            self.modules = ['baseline',] #'persistence', 'processes', 'signing', 'tcc',
                #'xattr', 'credentials','logs']
        for name in self.modules:
            module_class = self.registry[name]
            module = module_class()
            results[name] = module.collect()
        report_builder = ReportBuilder()
        report = report_builder.build(results, VERSION)
        return report
