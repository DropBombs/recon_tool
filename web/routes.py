from flask import Flask, request, jsonify
import subprocess
import os
from web.database import init_db, log_scan_result

# Macros
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECON_SCRIPT = os.path.join(BASE_DIR, '../core/automated_recon.sh')

app = Flask(__name__)

init_db()

@app.route('/api/v1/recon', methods=['POST'])
def trigger_recon():
	data = request.get_json()

	if not data or 'target' not in data:
		return jsonify({"error": "'target' parameter is required in the JSON payload."}), 400
	target = str(data['target']).strip()

	try:
		result = subprocess.run(
			['bash', RECON_SCRIPT, target],
			capture_output=True,
			text=True,
			check=True,
			timeout=300
		)

		output_data = result.stdout
		status_execution = "Success"

		# Persists data straight into local SQLite instance.
		log_scan_result(target, status_execution, output_data)

		return jsonify({
			"status": "Finished",
			"target": target,
			"engine_output": output_data
		}), 200

	except subprocess.CalledProcessError as e:
		error_msg = f"Bash engine error: {e.stderr}"
		log_scan_result(target, "Fail", error_msg)
		return jsonify({"error": "Error occurred while executing scan.", "details": e.stderr}), 500

	except subprocess.TimeoutExpired:
		error_msg = "Process exceeded the time limit."
		log_scan_result(target, "Timeout", error_msg)
		return jsonify({"error": "Execution exceeded the time limit."}), 504

if __name__ == '__main__':
	app.run(host='0.0.0.0', debug=True, port=5000)
