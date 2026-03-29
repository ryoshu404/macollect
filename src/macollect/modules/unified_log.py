import subprocess
from pathlib import Path


class UnifiedLog():

    depends_on = []
    inject = {}

    def __init__(self, time_window: int = 24):
        self.time_window = time_window

    def collect(self) -> dict:
        subsystems = [
            'com.apple.security',
            'com.apple.xpc',
            'com.apple.launchd',
            'com.apple.backgroundtaskmanagement',
            'com.apple.authorization',
            'com.apple.authenticate',
            ]
        data = {}
        for subsystem in subsystems:
            data[subsystem] = self._collect_subsystem(subsystem)
        flags = self._evaluate_flags(data)
        return {
            'data': data,
            'flags': flags
            }

    def _collect_subsystem(self, subsystem: str) -> dict:
        try:
            result = subprocess.run(
                    ['log', 'show',
                    '--predicate', f'subsystem == "{subsystem}"',
                    '--last', f'{self.time_window}h',
                    '--level', 
                    'error'
                    ],
                capture_output=True, text=True, timeout=60
                )
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            # first line is always the log header, skip it
            entries = lines[1:] if len(lines) > 1 else []
            return {
                'event_count': len(entries),
                'entries': entries[:25],
                }
        except subprocess.TimeoutExpired:
            return {'event_count': 0, 'entries': [], 'error': 'timeout'}
        except Exception as e:
            return {'event_count': 0, 'entries': [], 'error': str(e)}

    def _evaluate_flags(self, data: dict) -> list:
        return []