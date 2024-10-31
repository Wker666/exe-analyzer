from flask import Flask, render_template, request, jsonify,send_from_directory
from analysis.analyzer import Analyzer
from flask_cors import CORS
import argparse

app = Flask(__name__)
# 允许所有源访问
CORS(app)

@app.route('/')
def index():
    return render_template('index.html', svg_path='static/'+svg_path+".svg")


@app.route('/user_section',methods=['GET'])
def user_section():
    info = '不同环不同色，蓝色圈函数头，灰底色系统层'
    user_section={'app':analyzer.data['AppName'],'info':info,'UserCodeStartAddress':analyzer.data['UserCodeStartAddress'],'UserCodeStartSize':analyzer.data['UserCodeStartSize']}
    return jsonify(user_section),200

@app.route('/emulate', methods=['POST'])
def emulate():
    data = request.json
    log_address = data['log_address']
    if log_address:
        try:
            log_address_v = int(log_address, 16)
            analyzer.emulator.start_log_address = log_address_v
            analyzer.emulator.stop_log_address = log_address_v
            analyzer.emulator.data_map = {}
            analyzer.run_emulation(None, None)
            return jsonify(analyzer.emulator.data_map[log_address]), 200
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid address format."}), 400
        except KeyError:
            return jsonify({"status": "error", "message": "Not Found Address Info."}), 500
    return jsonify({"status": "error", "message": "Start or end address not provided."}), 400

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="exe any be.")
    parser.add_argument("-w","--workspace", help="work space")
    args = parser.parse_args()
    if not args.workspace:
        print("pls input workspace")
        exit(-1)
    global workspace
    global analyzer
    global svg_path
    workspace = args.workspace
    analyzer = Analyzer(workspace)
    svg_path = 'control_flow_graph'
    analyzer.generate_flowchart('static/'+svg_path)
    app.run(debug=True)
