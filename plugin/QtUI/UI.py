import os
from typing import Dict, Any

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt, QTranslator
from qfluentwidgets import  FluentTranslator

from Callbacks import Callbacks
from QtUI.SignalHandler import SignalHandler
from QtUI.Window.MainWindow import Window


class UI:
    def __init__(self):
        # enable dpi scale
        self.callbacks = None
        self.app = QApplication([])

        # if cfg.get(cfg.dpiScale) == "Auto":
        #     QApplication.setHighDpiScaleFactorRoundingPolicy(
        #         Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
        #     QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
        # else:
        #     os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "0"
        #     os.environ["QT_SCALE_FACTOR"] = str(cfg.get(cfg.dpiScale))
        # QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
        # self.app.setAttribute(Qt.AA_DontCreateNativeWidgetSiblings)
        # locale = cfg.get(cfg.language).value
        # self.app.installTranslator(FluentTranslator(locale))
        # gallery_translator = QTranslator()
        # gallery_translator.load(locale, "gallery", ".", ":/gallery/i18n")
        # self.app.installTranslator(gallery_translator)

        self.window = Window(self)
        self.signal_handler = SignalHandler(self.app)  # Create an instance of SignalHandler
        # self.ui = Ui_MainDialog()
        # self.ui.setupUi(self.window)
        self.window.show()

    # 这个方法将会在callback初始化的时候调用，所以放心使用callbacks
    def set_callbacks(self,callbacks: Callbacks):
        self.callbacks = callbacks

    def run(self):
        self.app.exec_()

    def quit(self):
        """Emit a signal to quit the application."""
        self.signal_handler.quit_signal.emit()  # Emit the quit signal

    def enter_dbg(self, dbg: int, pi: Dict[str, Any], process_name: str, dbg_name: str) -> int:
        return self.window.enter_dbg(dbg, pi, process_name, dbg_name)

    def exit_dbg(self, dbg: int):
        ret = self.window.exit_dbg(dbg)
        self.quit()
        return ret

    def unknow_exception_callback(self, dbg: int,ctx: Dict,exception: Dict) -> int:
        return self.window.unknow_exception_callback(dbg,ctx,exception)

    def bp_callback(self, dbg: int, bp: Dict[str, Any], ctx: Dict[str, Any]) -> int:
        return self.window.bp_callback(dbg, bp, ctx)

    def create_process_callback(self, dbg: int, create_process_debug_info: Dict[str, Any]) -> int:
        return self.window.create_process_callback(dbg, create_process_debug_info)

    def load_dll_callback(self, dbg: int, load_dll_debug_info: Dict[str, Any]) -> int:
        return self.window.load_dll_callback(dbg, load_dll_debug_info)

    def unload_dll_callback(self, dbg: int, unload_dll_debug_info: Dict[str, Any]) -> int:
        return self.window.unload_dll_callback(dbg, unload_dll_debug_info)

    def create_thread_callback(self, dbg: int, create_thread_debug_info: Dict[str, Any]) -> int:
        return self.window.create_thread_callback(dbg, create_thread_debug_info)

    def exit_thread_callback(self, dbg: int, exit_thread_debug_info: Dict[str, Any]) -> int:
        return self.window.exit_thread_callback(dbg, exit_thread_debug_info)

    def output_string_callback(self, dbg: int, debug_string: Dict[str, Any]) -> int:
        return self.window.output_string_callback(dbg, debug_string)

    def exit_process_callback(self, dbg: int, exit_process_debug_info: Dict[str, Any]) -> int:
        return self.window.exit_process_callback(dbg, exit_process_debug_info)
