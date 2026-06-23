from flask import Flask, request, jsonify
import subprocess
import os
import re
from database import init_db, log_scan_result

# Macros
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECON_SCRIPT = os.path.join(BASE_DIR, '../core/automated_recon.sh')

app = Flask(__name__)

init_db()

# Regex parsing
def parse_output(raw_stdout):
	structured_data = {
	"execution_checks": "",
	"whois_data": "",
	"nmap_data": "",
	"dns_data": "",
	"certificate_data": ""
	}

	header_pattern = r"==============\n\[\*\] (.*?) \[\*\]\n=============="

	matches = list(re.finditer(header_pattern, raw_stdout))

	if not matches:
		structured_data["execution_checks"] = raw_stdout.strip()
		return structured_data

	for index, match in enumerate(matches):
		section_title = match.group(1).lower()
		content_start = match.end()
		content_end = matches[index + 1].start() if index + 1 < len(matches) else len(raw_stdout)
		section_content = raw_stdout[content_start:content_end].strip()

		if "whois" in section_title:
			structured_data["whois_data"] = section_content
		elif "nmap" in section_title:
			structured_data["nmap_data"] = section_content
		elif "dns" in section_title:
			structured_data["dns_data"] = section_content
		elif "certificate" in section_title:
			structured_data["certificate_data"] = section_content

	return structured_data


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

		raw_output = result.stdout
		parsed_results = parse_output(raw_output)

		# Persists data straight into local SQLite instance.
		log_scan_result(target, "Success", raw_output)

		return jsonify({
			"status": "Finished",
			"target": target,
			"engine_output": parsed_results
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
