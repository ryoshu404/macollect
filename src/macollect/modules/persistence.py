


class Persistence():
    
    def collect(self) -> dict:
        persistence = {}
        persistence['btm'] = self._collect_btm() or ''
        persistence['launch_daemons'] = self._collect_launch_daemons() or []
        persistence['launch_agents'] = self._collect_launch_agents() or []
        persistence['login_items'] = self._collect_login_items() or []
        persistence['loginwindow'] = self._collect_loginwindow() or {}
        persistence['shell_configs'] = self._collect_shell_configs() or {}
        persistence['sudoers'] = self._collect_sudoers() or {}
        persistence['cron'] = self._collect_cron() or {}
        flags = self._evaluate_flag(persistence) or {}
        return {
            'data': persistence,
            'flags': flags
            }
    
    def _evaluate_flag(self, data: dict) -> list:
        pass
    
    def _collect_btm(self) -> str:
        pass

    def _collect_launch_daemons(self) -> list:
        pass

    def _collect_launch_agents(self) -> list:
        pass

    def _collect_login_items(self) -> list:
        pass
    
    def _collect_loginwindow(self) -> dict:
        pass

    def _collect_shell_configs(self) -> dict:
        pass

    def _collect_sudoers(self) -> dict:
        pass

    def _collect_cron(self) -> dict:
        pass