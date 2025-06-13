from flask import Flask, request, jsonify
import subprocess
import os
import logging
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)




@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/run-detector', methods=['GET'])
def run_detector():
    """Run the bucket security detector script"""
    
    print("Starting detector script")
    logger.info("Starting detector script")
    
    # Get the state_bucket from environment variables or use None (script will use default)
    state_bucket = os.environ.get('STATE_BUCKET', None)
    
    try:
        # Prepare command with optional state_bucket parameter
        cmd = ['bash', './detector.sh']
        if state_bucket:
            cmd.append(state_bucket)  # Pass as a single argument
            
        # Run the bash script with UTF-8 encoding
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='utf-8',
            errors='replace',
            text=True
        )
        
        # Capture output
        stdout, stderr = process.communicate()
        
        # Check if script execution was successful
        if process.returncode != 0:
            logger.error(f"Script failed with exit code {process.returncode}")
            return jsonify({
                'status': 'error',
                'exit_code': process.returncode,
                'stderr': stderr,
                'stdout': stdout
            }), 500
        
        # Process successful execution
        logger.info("Script completed successfully")
        
        # Parse the summary from stdout
        summary = {}
        if stdout:
            for line in stdout.splitlines():
                if "⚠️" in line:
                    parts = line.split(": ")
                    if len(parts) == 2:
                        key = parts[0].replace("⚠️", "").strip()
                        try:
                            value = int(parts[1])
                            summary[key] = value
                        except ValueError:
                            summary[key] = parts[1]
        
        return jsonify({
            'status': 'success',
            'summary': summary,
            'full_output': stdout,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logger.exception(f"Error running detector script: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # For local development only
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
