import threading
from typing import Dict, Any

from PyQt5.QtWidgets import QFrame,  QVBoxLayout, QHBoxLayout, QApplication
from keystone import  KS_ARCH_X86, KS_MODE_64, Ks
from qfluentwidgets import CommandBar, FluentIcon, Action, InfoBar, InfoBarPosition

import DbgModule
from DbgInfo import DbgConst
from DbgInfo.DbgConst import VEH_PROCESS
from QtUI import UI
from capstone import *

from QtUI.Widget.Tables.AssemblerTableWidget import *
from QtUI.Widget.Tables.MemoryTableWidget import MemoryTableWidget
from QtUI.Widget.Tables.RegisterTableWidget import RegisterTableWidget


class AssemblyWidget(QFrame):

    def __init__(self, ui:UI, parent=None):
        super().__init__(parent=parent)
        self.dbg = None
        # 汇编部分的
        self.cur_assembly_address = 0
        self.address_to_row_map = {}
        self.current_range_end = 0
        self.current_range_start = 0
        # 内存部分的
        self.cur_mem_addr = 0
        self.cur_mem_size = 0
        # 栈部分的
        self.cur_rsp = 0
        self.cur_rsp_size = 0x100

        self.ui = ui
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        # 创建Keystone引擎
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

        self.bp_next_step = -1

        self.assemblyTableView = AssemblerTableWidget(self.on_instruction_modified)
        self.registerTableView = RegisterTableWidget()

        self.vBoxLayout = QVBoxLayout(self)

        self.dbgCommandBar = CommandBar()
        self.dbgCommandBar.addAction(Action(FluentIcon.RIGHT_ARROW, '步过', triggered=lambda: (self.set_bp_next_step(DbgConst.CALLBACK_TYPE_SINGLE_STEP_STEP))))
        self.dbgCommandBar.addAction(Action(FluentIcon.ARROW_DOWN, '步入', triggered=lambda: (self.set_bp_next_step(DbgConst.CALLBACK_TYPE_SINGLE_INTO_STEP))))
        self.dbgCommandBar.addAction(Action(FluentIcon.CARE_RIGHT_SOLID, '运行', triggered=lambda: (self.set_bp_next_step(DbgConst.CALLBACK_TYPE_NONE))))

        self.hassemblyBoxLayout = QHBoxLayout(self)
        self.hassemblyBoxLayout.addWidget(self.assemblyTableView)
        self.hassemblyBoxLayout.addWidget(self.registerTableView)
        self.hassemblyBoxLayout.setStretchFactor(self.assemblyTableView, 8)
        self.hassemblyBoxLayout.setStretchFactor(self.registerTableView, 2)

        self.hMemBoxLayout = QHBoxLayout(self)
        self.MemView = MemoryTableWidget(mode='byte',change_callback=self.on_mem_change)
        self.StackView = MemoryTableWidget(mode='int',change_callback=self.on_mem_change)
        self.hMemBoxLayout.addWidget(self.MemView)
        self.hMemBoxLayout.addWidget(self.StackView)
        self.hMemBoxLayout.setStretchFactor(self.MemView, 7)
        self.hMemBoxLayout.setStretchFactor(self.StackView, 3)

        self.vBoxLayout.addWidget(self.dbgCommandBar)
        self.vBoxLayout.addLayout(self.hassemblyBoxLayout)
        self.vBoxLayout.addLayout(self.hMemBoxLayout)
        self.vBoxLayout.setStretchFactor(self.hassemblyBoxLayout, 7)
        self.vBoxLayout.setStretchFactor(self.hMemBoxLayout, 2)

        self.vBoxLayout.setContentsMargins(0, 33, 0, 0)

    def reload_assembly(self):
        # 由于数据量太大   python实在无法处理，所以现在修改为前后间距的方法
        spacing = 0x100
        address = self.cur_assembly_address - spacing
        size = 2 * spacing

        code = bytearray(size)
        DbgModule.read_mem(self.dbg, address, code)
        cur_run_idx = -1
        find_cnt = 0
        assembly_list = []
        self.address_to_row_map.clear()  # 清除旧的映射
        while cur_run_idx == -1:
            cur_code = code[find_cnt:]
            cur_cs_address = address + find_cnt
            assembly_list = []
            idx = 0
            total_size = 0
            while total_size < size:
                for cur_isn in self.cs.disasm(cur_code, cur_cs_address):
                    if cur_isn.address == self.cur_assembly_address:
                        cur_run_idx = idx
                    total_size += cur_isn.size
                    addr = hex(cur_isn.address)
                    addr = "0x" + addr[2:].upper()
                    assembly_list.append((addr, cur_isn.bytes.hex().upper(), cur_isn.mnemonic, cur_isn.op_str, ""))
                    self.address_to_row_map[cur_isn.address] = idx  # 更新地址到行的映射
                    idx += 1
                total_size += 1  # Skip unrecognized instructions
                offset = find_cnt + total_size
                cur_cs_address = address + offset
                cur_code = code[offset:]
            find_cnt += 1
        # 更新当前范围
        self.current_range_start = address
        self.current_range_end = address + size
        # 更新表格视图
        self.assemblyTableView.clear_bp_highlight()
        self.assemblyTableView.clear_cur_run_highlight()
        if threading.current_thread() == threading.main_thread():
            self.assemblyTableView.update_instructions(assembly_list)
        else:
            self.assemblyTableView.set_instructions(assembly_list)
        self.jump_to_address(self.cur_assembly_address)

    # 修改的汇编指令
    def on_instruction_modified(self, address, new_value):
        try:
            encoding, count = self.ks.asm(new_value)
            ret,wbytes = DbgModule.write_mem(self.dbg,address, bytearray(encoding))
            if not ret:
                raise Exception
            self.reload_assembly()
        except :
            InfoBar.error(
                title=self.tr('错误'),
                content=self.tr("汇编失败"),
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self
            )
        return

    def reload_stack(self):
        data = bytearray(self.cur_rsp_size*2)
        DbgModule.read_mem(self.dbg,self.cur_rsp - self.cur_rsp_size ,data)
        self.StackView.update_memory(self.cur_rsp - self.cur_rsp_size,data)

    def reload_mem(self):
        data = bytearray(self.cur_mem_size)
        DbgModule.read_mem(self.dbg,self.cur_mem_addr,data)
        self.MemView.update_memory(self.cur_mem_addr,data)

    def on_mem_change(self,address, value_str,type):
        try:
            hex_str = value_str.replace(" ", "").replace("0x", "")
            if len(hex_str) % 2 != 0:
                hex_str = '0' + hex_str
            byte_array = bytearray.fromhex(hex_str)
            if type == 1: # int方式
                byte_array = bytearray(8 - len(byte_array)) + byte_array
            byte_array.reverse()
            ret,wbytes = DbgModule.write_mem(self.dbg,address, byte_array)
            if type == 1: # int方式
                self.reload_stack()
            else:
                self.reload_mem()
            if not ret:
                raise Exception
        except:
            InfoBar.error(
                title=self.tr('错误'),
                content=self.tr("内存写入失败"),
                orient=Qt.Horizontal,
                isClosable=True,
                position=InfoBarPosition.TOP_RIGHT,
                duration=2000,
                parent=self
            )

    def set_bp_next_step(self, bp_next_step):
        self.bp_next_step = bp_next_step

    def load_assembly(self, dbg: int, address: int, size: int, cur_address: int):
        self.cur_assembly_address = cur_address
        # 检查 cur_address 是否在当前加载的范围内
        if (self.current_range_start is not None and
            self.current_range_end is not None and
            self.current_range_start <= cur_address < self.current_range_end):
            # 如果在范围内，直接跳转到指定位置
            self.jump_to_address(cur_address)
            return
        # 如果不在范围内，重新加载
        self.reload_assembly()

    def jump_to_address(self, cur_address):
        # 使用映射直接获取行索引
        row = self.address_to_row_map.get(cur_address)
        if row is not None:
            self.assemblyTableView.set_cur_run_highlight(row)
            self.assemblyTableView.instructionsScrollToItem.emit(row)

    def enter_dbg(self, dbg: int, pi: Dict[str, Any], process_name: str, dbg_name: str) -> int:
        self.dbg = dbg # 这里肯定会进入，所以在这里设置
        if process_name == VEH_PROCESS:
            # VEH此处可以加载
            # DbgModule.add_soft_bp(dbg, 0x00007FF7FCCE11EE)
            pass
        return DbgConst.CALLBACK_TYPE_NONE

    def exit_dbg(self, dbg: int):
        return DbgConst.CALLBACK_TYPE_NONE

    def unknow_exception_callback(self, dbg: int,ctx: Dict,exception: Dict) -> int:
        return self.process_exception(dbg,None,ctx,exception['ExceptionRecord']['ExceptionAddress'])

    def bp_callback(self, dbg: int, bp: Dict[str, Any], ctx: Dict[str, Any]) -> int:
        return self.process_exception(dbg,bp,ctx,ctx['Rip'])

    def process_exception(self,dbg: int,bp: Dict[str, Any],ctx: Dict[str, Any],exception_address: int) -> int:
        modules = self.find_section_for_address(DbgModule.get_modules(dbg),exception_address)

        self.load_assembly(dbg,modules['section_base_address'],modules['section_size'],exception_address)

        self.registerTableView.set_registers(ctx)
        self.registerTableView.registerChanged.connect(lambda reg, val: self.update_register(ctx,reg,val))
        self.cur_rsp  = ctx['Rsp']
        self.cur_rsp_size = 0x100
        self.reload_stack()
        self.bp_next_step = -1
        while self.bp_next_step == -1:
            QApplication.processEvents()
        return self.bp_next_step

    def update_register(self,ctx: Dict[str, Any], reg: str, val:str):
        ctx[reg] = int(val, 16)

    def create_process_callback(self, dbg: int, create_process_debug_info: Dict[str, Any]) -> int:
        self.cur_mem_addr = create_process_debug_info['lpBaseOfImage']
        self.cur_mem_size = 0x500
        self.reload_mem()
        DbgModule.add_soft_bp(dbg,create_process_debug_info['lpStartAddress'])
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

    def find_section_for_address(self,modules, target_address):
        for module_name, module_info in modules.items():
            base_address = module_info['baseAddress']
            size = module_info['size']
            if base_address <= target_address < base_address + size:
                for section in module_info['sections']:
                    section_base = section['baseAddress']
                    section_size = section['size']
                    if section_base <= target_address < section_base + section_size:
                        return {
                            'module': module_name,
                            'section_base_address': section_base,
                            'section_size': section_size
                        }
        return None