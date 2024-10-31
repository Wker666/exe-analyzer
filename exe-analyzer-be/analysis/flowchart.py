from graphviz import Digraph
from analysis.utils import detect_cycles
import os
import html

class FlowchartGenerator:
    def __init__(self, data, workspace):
        self.data = data
        self.cfg = data["cfg"]
        self.workspace = workspace
        self.func_address = data["func_addrss"]
        self.user_code_start_address = int(data["UserCodeStartAddress"], 16)
        self.user_code_end_address = self.user_code_start_address + int(data["UserCodeStartSize"], 16)

    def generate(self, svg_path):
        dot = Digraph(format='svg')

        address_color = "green"
        asm_color = "yellow"
        comment_bg_color = "white"
        comment_text_color = "red"
        non_user_code_color = "grey"
        func_node_color = "blue"

        address_to_block = {}
        for block_address, block_details in self.cfg.items():
            for insn in block_details['insns']:
                address_to_block[insn['address']] = block_address

        cycles = detect_cycles(self.cfg, address_to_block)

        for node, details in self.cfg.items():
            block_address = int(node, 16)
            is_in_user_code = self.user_code_start_address <= block_address < self.user_code_end_address
            node_label = f"<<table border='0' cellborder='1' cellspacing='0'>"
            if not is_in_user_code:
                node_label += f"<tr><td colspan='3' bgcolor='{non_user_code_color}'><b>{node} (Call Count: {details['call_cnt']})</b></td></tr>"
            else:
                node_label += f"<tr><td colspan='3' bgcolor='lightgrey'><b>{node} (Call Count: {details['call_cnt']})</b></td></tr>"

            for insn in details['insns']:
                insn_href = f"#insn-{insn['address']}"  # Customize this link as needed
                node_label += "<tr>"
                if is_in_user_code:
                    node_label += (
                        f"<td href='{insn_href}' bgcolor='{address_color}'>{insn['address']}</td>"
                        f"<td href='{insn_href}' bgcolor='{asm_color}'>{insn['asm']}</td>"
                    )
                    comment_content = insn['comment'].strip()
                    comment_content = ''.join(f'\\x{ord(c):02x}' if ord(c) < 32 or ord(c) > 126 else c for c in comment_content)
                    comment_content = html.escape(comment_content)
                    if comment_content:
                        node_label += f"<td href='{insn_href}' bgcolor='{comment_bg_color}'><font color='{comment_text_color}'>{comment_content}</font></td>"
                    else:
                        node_label += f"<td href='{insn_href}' bgcolor='{comment_bg_color}'>{comment_content}</td>"
                else:
                    # Use plain grey for non-user code
                    node_label += (
                        f"<td href='{insn_href}' bgcolor='{non_user_code_color}'>{insn['address']}</td>"
                        f"<td href='{insn_href}' bgcolor='{non_user_code_color}'>{insn['asm']}</td>"
                    )
                    comment_content = insn['comment'].strip()
                    node_label += f"<td href='{insn_href}' bgcolor='{non_user_code_color}'>{comment_content}</td>"

                node_label += "</tr>"
            node_label += "</table>>"

            # Determine the node style based on whether it is in func_address
            if node in self.func_address:
                dot.node(node, node_label, shape='circle', style='filled', fillcolor=func_node_color, href=f'#node-{node}')
            elif is_in_user_code:
                dot.node(node, node_label, shape='plaintext', href=f'#node-{node}')
            else:
                dot.node(node, node_label, shape='plaintext', style='filled', fillcolor=non_user_code_color, href=f'#node-{node}')

            if 'Successors' in details:
                for succ in details['Successors']:
                    succ_address = succ['address']
                    target_block = address_to_block.get(succ_address, succ_address)
                    edge_color = cycles.get((node, target_block), "#202020")
                    for from_addr, call_infos in succ['from'].items():
                        edge_label = f"Calls: {call_infos['cnt']}\nFrom: {from_addr}\nTarget:{call_infos['target']}"
                        dot.edge(node, target_block, label=edge_label, color=edge_color, href=f'#edge-{node}-{target_block}')

        # Save the SVG to a file
        dot.render(svg_path, cleanup=True)
        print(f"Control flow chart has been generated and saved as {svg_path}.svg")
