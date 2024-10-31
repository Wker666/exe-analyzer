import json,os
from analysis.flowchart import FlowchartGenerator
from analysis.emulator import Emulator

class Analyzer:
    def __init__(self, workspace):
        self.workspace = workspace
        self.data = self.load_json(os.path.join(self.workspace, 'work.json'))
        self.flowchart_generator = FlowchartGenerator(self.data, self.workspace)
        self.emulator = Emulator(self.data, self.workspace)

    def load_json(self, file_path):
        with open(file_path, 'r') as f:
            return json.load(f)

    def generate_flowchart(self,svg_path):
        self.flowchart_generator.generate(svg_path)

    def run_emulation(self, start_address=None, end_address=None):
        self.emulator.emulate(start_address, end_address)