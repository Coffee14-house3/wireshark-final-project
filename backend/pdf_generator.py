#protocol analyzer backend file
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
import os
import logging

logger = logging.getLogger(__name__)

def generate_pdf_report(analysis_results, original_filename):
    """Generate a PDF report from the PCAP analysis results."""
    try:
        pdf_filename = f"reports/{original_filename}_report.pdf"
        doc = SimpleDocTemplate(
            pdf_filename,
            pagesize=landscape(letter),
            rightMargin=30,
            leftMargin=30,
            topMargin=30,
            bottomMargin=30
        )
        
        styles = getSampleStyleSheet()
        custom_style = ParagraphStyle(
            'CustomStyle',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=20
        )
        
        elements = []
        
        # Add title and summary
        elements.append(Paragraph(f"PCAP Analysis Report - {original_filename}", styles['Title']))
        elements.append(Spacer(1, 20))
        
        # Add summary table
        summary_data = [
            ['Total Packets', str(analysis_results['packet_count'])],
            ['Total Bytes', str(analysis_results['byte_count'])],
        ]
        
        summary_table = Table(summary_data, colWidths=[200, 200])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 20))
        
        # Protocol distribution
        if 'protocols' in analysis_results:
            elements.append(Paragraph("PCAP REPORT", styles['Heading2']))
            protocol_data = [[protocol, count] for protocol, count in analysis_results['protocols'].items()]
            if protocol_data:
                protocol_table = Table([['Protocol', 'Count']] + protocol_data)
                protocol_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ]))
                elements.append(protocol_table)
                elements.append(Spacer(1, 20))
        
        # Create packet details table
        table_data = [
            ['#', 'Time', 'Source IP', 'Dest IP', 'Protocol', 'Src Port', 'Dst Port', 'Length', 'Flags']
        ]
        
        for idx, packet in enumerate(analysis_results['packets'], 1):
            row = [
                str(idx),
                str(packet.get('timestamp', 'N/A'))[:19],
                packet.get('src_ip', 'N/A'),
                packet.get('dst_ip', 'N/A'),
                packet.get('protocol_name', 'N/A'),
                str(packet.get('src_port', 'N/A')),
                str(packet.get('dst_port', 'N/A')),
                str(packet.get('length', 'N/A')),
                str(packet.get('flags', 'N/A'))
            ]
            table_data.append(row)
        
        # Create and style the table
        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(table)
        doc.build(elements)
        return pdf_filename
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        raise