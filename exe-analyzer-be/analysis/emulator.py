from unicorn import *
from unicorn.x86_const import *
from analysis.utils import load_memory_to_unicorn, set_registers

class Emulator:
    def __init__(self, data, workspace):
        self.data = data
        self.workspace = workspace
        self.unicorn_data = data['unicorn']
        self.default_start_address = int(data.get('StartAddress'), 16)
        self.default_end_address = int(data.get('EndAddress'), 16)
        self.user_code_start = int(data.get('UserCodeStartAddress'), 16)
        self.user_code_end = self.user_code_start + int(data.get('UserCodeStartSize'), 16)
        self.g_pre_addree = 0
        self.start_log_address = 0
        self.stop_log_address = 0
        self.is_logging = False
        self.data_map = {}
    
    def sub_hook_code(self, mu, address, size, user_data):
        if address == self.start_log_address:
            self.is_logging = True
        if self.is_logging:
            # start logging
            self.data_map[f'0x{address:016X}'] = {}
            self.capture_registers(mu,address)
            self.capture_memory(mu,address)
            pass
        if address == self.stop_log_address:
            self.is_logging = False
    
    def capture_registers(self, mu, address):
        """捕获所有寄存器的值并存储在 data_map 中"""
        self.data_map[f'0x{address:016X}']['reg'] = {
            'rax': f'0x{mu.reg_read(UC_X86_REG_RAX):016X}',
            'rbx': f'0x{mu.reg_read(UC_X86_REG_RBX):016X}',
            'rcx': f'0x{mu.reg_read(UC_X86_REG_RCX):016X}',
            'rdx': f'0x{mu.reg_read(UC_X86_REG_RDX):016X}',
            'rsi': f'0x{mu.reg_read(UC_X86_REG_RSI):016X}',
            'rdi': f'0x{mu.reg_read(UC_X86_REG_RDI):016X}',
            'rbp': f'0x{mu.reg_read(UC_X86_REG_RBP):016X}',
            'rsp': f'0x{mu.reg_read(UC_X86_REG_RSP):016X}',
            'r8':  f'0x{mu.reg_read(UC_X86_REG_R8):016X}',
            'r9':  f'0x{mu.reg_read(UC_X86_REG_R9):016X}',
            'r10': f'0x{mu.reg_read(UC_X86_REG_R10):016X}',
            'r11': f'0x{mu.reg_read(UC_X86_REG_R11):016X}',
            'r12': f'0x{mu.reg_read(UC_X86_REG_R12):016X}',
            'r13': f'0x{mu.reg_read(UC_X86_REG_R13):016X}',
            'r14': f'0x{mu.reg_read(UC_X86_REG_R14):016X}',
            'r15': f'0x{mu.reg_read(UC_X86_REG_R15):016X}',
            'rip': f'0x{mu.reg_read(UC_X86_REG_RIP):016X}',
            'eflags': f'0x{mu.reg_read(UC_X86_REG_EFLAGS):08X}',
            'xmm0': f'0x{mu.reg_read(UC_X86_REG_XMM0):032X}',
            'xmm1': f'0x{mu.reg_read(UC_X86_REG_XMM1):032X}',
            'xmm2': f'0x{mu.reg_read(UC_X86_REG_XMM2):032X}',
            'xmm3': f'0x{mu.reg_read(UC_X86_REG_XMM3):032X}',
            'xmm4': f'0x{mu.reg_read(UC_X86_REG_XMM4):032X}',
            'xmm5': f'0x{mu.reg_read(UC_X86_REG_XMM5):032X}',
            'xmm6': f'0x{mu.reg_read(UC_X86_REG_XMM6):032X}',
            'xmm7': f'0x{mu.reg_read(UC_X86_REG_XMM7):032X}',
            'xmm8': f'0x{mu.reg_read(UC_X86_REG_XMM8):032X}',
            'xmm9': f'0x{mu.reg_read(UC_X86_REG_XMM9):032X}',
            'xmm10': f'0x{mu.reg_read(UC_X86_REG_XMM10):032X}',
            'xmm11': f'0x{mu.reg_read(UC_X86_REG_XMM11):032X}',
            'xmm12': f'0x{mu.reg_read(UC_X86_REG_XMM12):032X}',
            'xmm13': f'0x{mu.reg_read(UC_X86_REG_XMM13):032X}',
            'xmm14': f'0x{mu.reg_read(UC_X86_REG_XMM14):032X}',
            'xmm15': f'0x{mu.reg_read(UC_X86_REG_XMM15):032X}'
        }

    def capture_memory(self, mu, address):
        """遍历并保存所有映射的内存区域"""
        self.data_map[f'0x{address:016X}']['mem_map'] = {}
        memory_regions = mu.mem_regions()
        for start, end, perms in memory_regions:
            # 读取内存内容
            size = end - start
            memory_content = mu.mem_read(start, size)
            # 将内存内容和权限信息存储到 data_map
            self.data_map[f'0x{address:016X}']['mem_map'][f'0x{start:016X}'] = {
                'end': f'0x{end:016X}',
                'permissions': perms,
                'content': memory_content.hex()
            }

    
    def hook_code(self,mu, address, size, user_data):
        self.g_pre_addree = address
        self.sub_hook_code(mu, address, size, user_data)
    
    
    def emulate(self, start_address=None, end_address=None):
        error_counts = {}
        start_address = start_address or self.default_start_address
        end_address = end_address or self.default_end_address
        while True:
            current_rip = f"0x{start_address:016X}"
            if current_rip not in self.unicorn_data:
                print(f"RIP {current_rip} not found in JSON data.")
                break
            reg_list = self.unicorn_data[current_rip]
            idx = error_counts.get(current_rip, 0)
            if idx >= len(reg_list):
                # 此处一般进入了exit
                print(f"All states exhausted for RIP {current_rip}. Stopping emulation.")
                break
            reg_info = reg_list[idx]
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            set_registers(uc, reg_info)
            for mem_addr in reg_info['mem']:
                load_memory_to_unicorn(uc, int(mem_addr, 16), f"{self.workspace}/mem/{reg_info['mem'][mem_addr]}")
            try:
                uc.hook_add(UC_HOOK_CODE, self.hook_code)
                uc.emu_start(int(reg_info['next_rip'], 16), end_address)
                print(f"Emulation finished without errors at RIP {f'0x{uc.reg_read(UC_X86_REG_RIP):016X}'}.")
                break
            except UcError as e:
                error_counts[current_rip] = idx + 1
                start_address = uc.reg_read(UC_X86_REG_RIP)
                if e.errno == UC_ERR_FETCH_UNMAPPED or (self.user_code_start <= start_address < self.user_code_end):
                    start_address = self.g_pre_addree
                print(f"Emulation error at RIP {f'0x{start_address:016X}'}, idx {idx}: {e}")

