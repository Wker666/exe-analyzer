from typing import Dict

from DbgInfo import DbgConst
from QtUI.UI import UI
from SubCallback.UiCallbacks import UiCallbacks

# Global instances
ui_instance = UI()
callbacks_instance = UiCallbacks(ui_instance)

def main_loop(version: float) -> int:
    global ui_instance
    if ui_instance is not None:
        ui_instance.run()
    return DbgConst.CALLBACK_TYPE_NONE

def enter_dbg(dbg: int, pi: Dict, process_name: str, dbg_name: str) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.enter_dbg(dbg, pi, process_name, dbg_name)
    return DbgConst.CALLBACK_TYPE_NONE

def exit_dbg(dbg: int) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.exit_dbg(dbg)
    return DbgConst.CALLBACK_TYPE_NONE

def unknow_exception_callback(dbg: int,ctx: Dict,exception: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.unknow_exception_callback(dbg,ctx,exception)
    return DbgConst.CALLBACK_TYPE_NONE


def bp_callback(dbg: int, bp: Dict, ctx: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.bp_callback(dbg, bp, ctx)
    return DbgConst.CALLBACK_TYPE_NONE


def create_process_callback(dbg: int, create_process_debug_info: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.create_process_callback(dbg, create_process_debug_info)
    return DbgConst.CALLBACK_TYPE_NONE


def load_dll_callback(dbg: int, load_dll_debug_info: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.load_dll_callback(dbg, load_dll_debug_info)
    return DbgConst.CALLBACK_TYPE_NONE


def unload_dll_callback(dbg: int, unload_dll_debug_info: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.unload_dll_callback(dbg, unload_dll_debug_info)
    return DbgConst.CALLBACK_TYPE_NONE


def create_thread_callback(dbg: int, create_thread_debug_info: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.create_thread_callback(dbg, create_thread_debug_info)
    return DbgConst.CALLBACK_TYPE_NONE


def exit_thread_callback(dbg: int, exit_thread_debug_info: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.exit_thread_callback(dbg, exit_thread_debug_info)
    return DbgConst.CALLBACK_TYPE_NONE


def output_string_callback(dbg: int, debug_string: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.output_string_callback(dbg, debug_string)
    return DbgConst.CALLBACK_TYPE_NONE


def exit_process_callback(dbg: int, exit_process_debug_info: Dict) -> int:
    global callbacks_instance
    if callbacks_instance is not None:
        return callbacks_instance.exit_process_callback(dbg, exit_process_debug_info)
    return DbgConst.CALLBACK_TYPE_NONE
