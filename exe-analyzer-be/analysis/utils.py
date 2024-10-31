import colorsys
from unicorn import *
from unicorn.x86_const import *

def generate_color(index):
    hue = (index * 0.618033988749895) % 1
    lightness = 0.5
    saturation = 0.95
    return colorsys.hls_to_rgb(hue, lightness, saturation)

def rgb_to_hex(rgb):
    return '#{:02x}{:02x}{:02x}'.format(int(rgb[0]*255), int(rgb[1]*255), int(rgb[2]*255))

def detect_cycles(graph, address_to_block):
    visited = set()
    cycle_edges = []
    node_to_cycle_index = {}

    def visit(node, path):
        if node in path:
            cycle_start_index = path.index(node)
            cycle = path[cycle_start_index:]
            cycle_edges.append(cycle)
            return
        path.append(node)
        visited.add(node)
        if 'Successors' in graph[node]:
            for succ in graph[node]['Successors']:
                target_block = address_to_block.get(succ['address'], succ['address'])
                if target_block not in visited or target_block in path:
                    visit(target_block, path)
        path.pop()

    for node in graph:
        if node not in visited:
            visit(node, [])

    for index, cycle in enumerate(cycle_edges):
        color = rgb_to_hex(generate_color(index))
        for i in range(len(cycle)):
            node_to_cycle_index[(cycle[i], cycle[(i + 1) % len(cycle)])] = color

    return node_to_cycle_index

def load_memory_to_unicorn(uc, base_address, mem_file):
    with open(mem_file, 'rb') as f:
        mem_data = f.read()
        mem_size = len(mem_data)
        uc.mem_map(base_address, mem_size)
        uc.mem_write(base_address, mem_data)

def set_registers(uc, reg_info):
    uc.reg_write(UC_X86_REG_RIP, reg_info['rip'])
    uc.reg_write(UC_X86_REG_RAX, reg_info['rax'])
    uc.reg_write(UC_X86_REG_RBX, reg_info['rbx'])
    uc.reg_write(UC_X86_REG_RCX, reg_info['rcx'])
    uc.reg_write(UC_X86_REG_RDX, reg_info['rdx'])
    uc.reg_write(UC_X86_REG_RSI, reg_info['rsi'])
    uc.reg_write(UC_X86_REG_RDI, reg_info['rdi'])
    uc.reg_write(UC_X86_REG_RBP, reg_info['rbp'])
    uc.reg_write(UC_X86_REG_RSP, reg_info['rsp'])
    uc.reg_write(UC_X86_REG_R8, reg_info['r8'])
    uc.reg_write(UC_X86_REG_R9, reg_info['r9'])
    uc.reg_write(UC_X86_REG_R10, reg_info['r10'])
    uc.reg_write(UC_X86_REG_R11, reg_info['r11'])
    uc.reg_write(UC_X86_REG_R12, reg_info['r12'])
    uc.reg_write(UC_X86_REG_R13, reg_info['r13'])
    uc.reg_write(UC_X86_REG_R14, reg_info['r14'])
    uc.reg_write(UC_X86_REG_R15, reg_info['r15'])
    for i, xmm in enumerate(reg_info['xmm']):
        uc.reg_write(UC_X86_REG_XMM0 + i, (xmm['high'] << 64) | xmm['low'])

