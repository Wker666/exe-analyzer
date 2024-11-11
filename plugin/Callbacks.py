from typing import Dict, Any
from DbgInfo import DbgConst


class Callbacks:
    def unknow_exception_callback(self, dbg: int,ctx: Dict,exception: Dict) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def enter_dbg(self, dbg: int, pi: Dict[str, Any], process_name: str, dbg_name: str) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def bp_callback(self, dbg: int, bp: Dict[str, Any], ctx: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def create_process_callback(self, dbg: int, create_process_debug_info: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def load_dll_callback(self, dbg: int, load_dll_debug_info: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def unload_dll_callback(self, dbg: int, unload_dll_debug_info: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def create_thread_callback(self, dbg: int, create_thread_debug_info: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def exit_thread_callback(self, dbg: int, exit_thread_debug_info: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def output_string_callback(self, dbg: int, debug_string: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def exit_process_callback(self, dbg: int, exit_process_debug_info: Dict[str, Any]) -> int:
        return DbgConst.CALLBACK_TYPE_NONE

    def exit_dbg(self, dbg: int):
        return DbgConst.CALLBACK_TYPE_NONE