from flask import Flask, request, send_file, jsonify, Blueprint
import os
import logging
from werkzeug.utils import secure_filename
from pcap_analyzer import analyze_pcap
from pdf_generator import generate_pdf_report  # Ensure this module exists

# Create Flask Blueprint
protocol_api = Blueprint("protocol_api", __name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration Constants
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB limit

# Ensure required directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

def allowed_file(filename):
    """Check if the uploaded file has a valid extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@protocol_api.route('/upload', methods=['POST'])
def upload_file():
    """Handle PCAP file upload, process it, and return the analysis report."""
    try:
        # Check if file is present in the request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only .pcap and .pcapng files are allowed'}), 400
        
        # Secure filename and save it
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        logger.info(f"File uploaded successfully: {filename}")

        try:
            # Analyze the PCAP file
            analysis_results = analyze_pcap(filepath)
            if not analysis_results:
                raise ValueError("Empty analysis results")

            # Generate PDF report
            pdf_path = generate_pdf_report(analysis_results, filename)

            # Remove uploaded file after processing
            os.remove(filepath)

            return jsonify({
                'success': True,
                'message': 'Analysis complete',
                'download_url': f'/download/{os.path.basename(pdf_path)}'
            })

        except Exception as e:
            logger.error(f"Error processing file {filename}: {str(e)}")
            if os.path.exists(filepath):
                os.remove(filepath)
            return jsonify({'error': 'Error processing PCAP file'}), 500

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': 'Error uploading file'}), 500

@protocol_api.route('/download/<filename>')
def download_file(filename):
    """Serve the generated PDF report."""
    try:
        report_path = os.path.join(REPORTS_FOLDER, filename)
        if not os.path.exists(report_path):
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            report_path,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Error downloading file'}), 500