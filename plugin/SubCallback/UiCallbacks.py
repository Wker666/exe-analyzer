from typing import Dict, Any
from QtUI import UI
from Callbacks import Callbacks

class UiCallbacks(Callbacks):

    def __init__(self,ui: UI):
        self.UI = ui
        self.g_dbg = None
        self.info = {}
        self.UI.set_callbacks(self) # 初始化的时候就需要赋值

    def enter_dbg(self, dbg: int, pi: Dict[str, Any], process_name: str, dbg_name: str) -> int:
        self.g_dbg = dbg # 设置调试器
        self.info['process_name'] = process_name
        self.info['dbg_name'] = dbg_name
        return self.UI.enter_dbg(dbg, pi, process_name, dbg_name)

    def exit_dbg(self, dbg: int):
        return self.UI.exit_dbg(dbg)

    def unknow_exception_callback(self, dbg: int,ctx: Dict,exception: Dict) -> int:
        return self.UI.unknow_exception_callback(dbg,ctx,exception)

    def bp_callback(self, dbg: int, bp: Dict[str, Any], ctx: Dict[str, Any]) -> int:
        return self.UI.bp_callback(dbg, bp, ctx)
        # if not bp:
        #     print("Single step")
        #     return DbgConst.CALLBACK_TYPE_NONE
        # elif bp['one_time']:
        #     print("Step step")
        #     return DbgConst.CALLBACK_TYPE_NONE
        # DbgModule.set_bp_one_time(dbg, bp, True)

    def create_process_callback(self, dbg: int, create_process_debug_info: Dict[str, Any]) -> int:
        self.info['create_process_debug_info'] = create_process_debug_info
        return self.UI.create_process_callback(dbg, create_process_debug_info)

    def load_dll_callback(self, dbg: int, load_dll_debug_info: Dict[str, Any]) -> int:
        if 'load_dll_debug_info' not in self.info:
            self.info['load_dll_debug_info'] = []
        self.info['load_dll_debug_info'].append(load_dll_debug_info)
        return self.UI.load_dll_callback(dbg, load_dll_debug_info)

    def unload_dll_callback(self, dbg: int, unload_dll_debug_info: Dict[str, Any]) -> int:
        if 'unload_dll_debug_info' not in self.info:
            self.info['unload_dll_debug_info'] = []
        self.info['unload_dll_debug_info'].append(unload_dll_debug_info)
        return self.UI.unload_dll_callback(dbg, unload_dll_debug_info)

    def create_thread_callback(self, dbg: int, create_thread_debug_info: Dict[str, Any]) -> int:
        if 'create_thread_debug_info' not in self.info:
            self.info['create_thread_debug_info'] = []
        self.info['create_thread_debug_info'].append(create_thread_debug_info)
        return self.UI.create_thread_callback(dbg, create_thread_debug_info)

    def exit_thread_callback(self, dbg: int, exit_thread_debug_info: Dict[str, Any]) -> int:
        if 'exit_thread_debug_info' not in self.info:
            self.info['exit_thread_debug_info'] = []
        self.info['exit_thread_debug_info'].append(exit_thread_debug_info)
        return self.UI.exit_thread_callback(dbg, exit_thread_debug_info)

    def output_string_callback(self, dbg: int, debug_string: Dict[str, Any]) -> int:
        if 'debug_string' not in self.info:
            self.info['debug_string'] = []
        self.info['debug_string'].append(debug_string)
        return self.UI.output_string_callback(dbg, debug_string)

    def exit_process_callback(self, dbg: int, exit_process_debug_info: Dict[str, Any]) -> int:
        self.info['exit_process_debug_info'] = exit_process_debug_info
        return self.UI.exit_process_callback(dbg, exit_process_debug_info)
