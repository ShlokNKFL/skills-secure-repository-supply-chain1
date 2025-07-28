import os
import subprocess
from flask import Flask, request, send_file, jsonify

app = Flask(__name__)

# Base directory for file operations
BASE_DIR = "/var/www/uploads"

@app.route('/download', methods=['GET'])
def download_file():
    """VULNERABLE: Path traversal vulnerability"""
    filename = request.args.get('file')
    
    if not filename:
        return jsonify({"error": "No file specified"}), 400
    
    # VULNERABLE: Direct path concatenation without validation
    file_path = os.path.join(BASE_DIR, filename)
    
    try:
        # VULNERABLE: No validation against directory traversal
        return send_file(file_path, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404

@app.route('/read', methods=['GET'])
def read_file():
    """VULNERABLE: Another path traversal example"""
    filename = request.args.get('filename')
    
    if not filename:
        return jsonify({"error": "No filename provided"}), 400
    
    # VULNERABLE: Direct string concatenation for file path
    full_path = BASE_DIR + "/" + filename
    
    try:
        # VULNERABLE: Opening file without path validation
        with open(full_path, 'r') as file:
            content = file.read()
        return jsonify({"content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/execute', methods=['POST'])
def execute_command():
    """VULNERABLE: Command injection vulnerability"""
    data = request.get_json()
    command = data.get('command')
    
    if not command:
        return jsonify({"error": "No command provided"}), 400
    
    try:
        # VULNERABLE: Direct execution of user input
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logs', methods=['GET'])
def view_logs():
    """VULNERABLE: Path traversal in log viewing"""
    log_type = request.args.get('type', 'application')
    date = request.args.get('date', '2024-01-01')
    
    # VULNERABLE: User input directly used in file path
    log_filename = f"{log_type}_{date}.log"
    log_path = f"/var/log/myapp/{log_filename}"
    
    try:
        # VULNERABLE: No validation of constructed path
        with open(log_path, 'r') as log_file:
            logs = log_file.readlines()
        return jsonify({"logs": logs})
    except FileNotFoundError:
        return jsonify({"error": "Log file not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/backup', methods=['POST'])
def create_backup():
    """VULNERABLE: Command injection through file operations"""
    data = request.get_json()
    backup_name = data.get('backup_name', 'default_backup')
    
    # VULNERABLE: User input in shell command
    backup_command = f"tar -czf /backups/{backup_name}.tar.gz /var/www/data"
    
    try:
        # VULNERABLE: Shell injection possible through backup_name
        result = os.system(backup_command)
        if result == 0:
            return jsonify({"message": "Backup created successfully"})
        else:
            return jsonify({"error": "Backup failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)