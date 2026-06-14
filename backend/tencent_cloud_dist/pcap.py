import os
import logging
import traceback
from flask import Blueprint, render_template, request, jsonify
from werkzeug.utils import secure_filename
import tempfile
import matplotlib.pyplot as plt
from analyzer import analyze_pcap_for_web

# Create Flask Blueprint
pcap_api = Blueprint("pcap_api", __name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure upload settings
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#@pcap_api.route('/')
#def index():
#   """Render the index page."""
#   return render_template('pcap_index.html')

@pcap_api.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and PCAP analysis."""
    try:
        logger.info("Starting file upload process")

        if 'file' not in request.files:
            logger.error('No file part in request')
            return jsonify({'error': 'No file part'}), 400

        file = request.files['file']
        if file.filename == '':
            logger.error('No selected file')
            return jsonify({'error': 'No selected file'}), 400

        if not allowed_file(file.filename):
            logger.error(f'Invalid file type: {file.filename}')
            return jsonify({'error': 'Invalid file type. Please upload a PCAP file'}), 400

        # Secure filename and save temporarily
        filename = secure_filename(file.filename)
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as temp_file:
            filepath = temp_file.name
            logger.info(f'Saving uploaded file to: {filepath}')
            file.save(filepath)

        try:
            logger.info('Starting PCAP analysis')
            plots = analyze_pcap_for_web(filepath)

            # Clean up temporary file
            logger.info('Cleaning up uploaded file')
            os.remove(filepath)

            logger.info('Analysis completed successfully')
            return jsonify(plots)

        except Exception as e:
            logger.error(f"Error during PCAP analysis: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")

            # Ensure cleanup even on error
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': f'Error analyzing PCAP file: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Unexpected error during upload: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500
