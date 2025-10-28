"""
Report Generation System

This module creates comprehensive security reports from vulnerability analysis results
in multiple formats (HTML, PDF, JSON).
"""

import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from ai_analyzer import VulnerabilityAnalysis

logger = logging.getLogger(__name__)


class ReportGenerationError(Exception):
    """Custom exception for report generation errors"""
    pass


class SecurityReportGenerator:
    """
    Generates comprehensive security reports in multiple formats
    """
    
    def __init__(self, template_dir: str = None, output_dir: str = None):
        """
        Initialize the report generator
        
        Args:
            template_dir (str): Directory containing report templates
            output_dir (str): Directory for generated reports
        """
        self.template_dir = template_dir or os.path.join(os.getcwd(), 'templates')
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'reports')
        
        # Ensure directories exist
        Path(self.template_dir).mkdir(parents=True, exist_ok=True)
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.template_dir),
                autoescape=True
            )
            logger.info(f"Initialized report generator with template dir: {self.template_dir}")
        except Exception as e:
            logger.error(f"Failed to initialize Jinja2 environment: {e}")
            raise ReportGenerationError(f"Template engine initialization failed: {e}")
    
    def generate_report_data(self, 
                           app_info: Dict[str, Any],
                           categorized_vulnerabilities: Dict[str, List[VulnerabilityAnalysis]],
                           executive_summary: str,
                           scan_stats: Dict[str, Any],
                           countermeasures: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Prepare report data for template rendering
        
        Args:
            app_info (Dict[str, Any]): Application metadata
            categorized_vulnerabilities (Dict[str, List[VulnerabilityAnalysis]]): Categorized vulnerabilities
            executive_summary (str): Executive summary text
            scan_stats (Dict[str, Any]): Scan statistics
            countermeasures (Dict[str, Any]): AI-generated countermeasures and action plan
            
        Returns:
            Dict[str, Any]: Complete report data
        """
        report_id = str(uuid.uuid4())[:8]
        current_time = datetime.now()
        
        # Convert VulnerabilityAnalysis objects to dictionaries for template rendering
        template_vulnerabilities = {}
        for severity, vulns in categorized_vulnerabilities.items():
            template_vulnerabilities[severity] = []
            for vuln in vulns:
                vuln_dict = {
                    'vulnerability_id': vuln.vulnerability_id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'impact': vuln.impact,
                    'recommendation': vuln.recommendation,
                    'priority': {
                        'severity': vuln.priority.severity,
                        'priority_score': vuln.priority.priority_score,
                        'reasoning': vuln.priority.reasoning,
                        'category': vuln.priority.category
                    },
                    'technical_details': vuln.technical_details
                }
                template_vulnerabilities[severity].append(vuln_dict)
        
        report_data = {
            'report_id': report_id,
            'app_name': app_info.get('app_name', 'Unknown Application'),
            'package_name': app_info.get('package_name', 'Unknown Package'),
            'version': app_info.get('version', 'Unknown Version'),
            'scan_date': app_info.get('scan_date', current_time.strftime('%Y-%m-%d %H:%M:%S')),
            'report_date': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'executive_summary': executive_summary,
            'vulnerabilities': template_vulnerabilities,
            'countermeasures': countermeasures,
            'stats': scan_stats,
            'total_vulnerabilities': sum(len(vulns) for vulns in categorized_vulnerabilities.values()),
            'metadata': {
                'generator': 'Mobile Security Agent',
                'version': '1.0.0',
                'scan_type': app_info.get('scan_type', 'Static Analysis')
            }
        }
        
        return report_data
    
    def generate_html_report(self, 
                           report_data: Dict[str, Any],
                           template_name: str = 'report_template.html',
                           output_filename: str = None) -> str:
        """
        Generate HTML security report
        
        Args:
            report_data (Dict[str, Any]): Report data
            template_name (str): Template file name
            output_filename (str): Output file name (auto-generated if None)
            
        Returns:
            str: Path to generated HTML report
        """
        logger.info("Generating HTML security report")
        
        try:
            # Load and render template
            template = self.jinja_env.get_template(template_name)
            html_content = template.render(**report_data)
            
            # Generate output filename if not provided
            if not output_filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                app_name = report_data['app_name'].replace(' ', '_')
                output_filename = f"security_report_{app_name}_{timestamp}.html"
            
            # Write HTML file
            output_path = os.path.join(self.output_dir, output_filename)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise ReportGenerationError(f"HTML report generation failed: {e}")
    
    def generate_pdf_report(self, 
                          report_data: Dict[str, Any],
                          output_filename: str = None) -> str:
        """
        Generate PDF security report
        
        Args:
            report_data (Dict[str, Any]): Report data
            output_filename (str): Output file name (auto-generated if None)
            
        Returns:
            str: Path to generated PDF report
        """
        logger.info("Generating PDF security report")
        
        try:
            # Generate output filename if not provided
            if not output_filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                app_name = report_data['app_name'].replace(' ', '_')
                output_filename = f"security_report_{app_name}_{timestamp}.pdf"
            
            output_path = os.path.join(self.output_dir, output_filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build PDF content
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=HexColor('#007acc'),
                alignment=TA_CENTER,
                spaceAfter=30
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=HexColor('#333333'),
                spaceBefore=20,
                spaceAfter=12
            )
            
            # Title page
            story.append(Paragraph("Mobile Application Security Report", title_style))
            story.append(Spacer(1, 20))
            
            # App information table
            app_info_data = [
                ['Application Name', report_data['app_name']],
                ['Package Name', report_data['package_name']],
                ['Scan Date', report_data['scan_date']],
                ['Report Generated', report_data['report_date']],
                ['Report ID', report_data['report_id']]
            ]
            
            app_info_table = Table(app_info_data, colWidths=[2.5*inch, 3.5*inch])
            app_info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#333333')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dddddd'))
            ]))
            
            story.append(app_info_table)
            story.append(Spacer(1, 30))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            story.append(Paragraph(report_data['executive_summary'], styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Vulnerability Statistics
            story.append(Paragraph("Vulnerability Statistics", heading_style))
            
            stats_data = [
                ['Severity Level', 'Count', 'Percentage'],
                ['Critical', str(report_data['stats']['severity_breakdown']['critical']), 
                 f"{(report_data['stats']['severity_breakdown']['critical'] / report_data['total_vulnerabilities'] * 100):.1f}%" if report_data['total_vulnerabilities'] > 0 else "0%"],
                ['High', str(report_data['stats']['severity_breakdown']['high']), 
                 f"{(report_data['stats']['severity_breakdown']['high'] / report_data['total_vulnerabilities'] * 100):.1f}%" if report_data['total_vulnerabilities'] > 0 else "0%"],
                ['Medium', str(report_data['stats']['severity_breakdown']['medium']), 
                 f"{(report_data['stats']['severity_breakdown']['medium'] / report_data['total_vulnerabilities'] * 100):.1f}%" if report_data['total_vulnerabilities'] > 0 else "0%"],
                ['Low', str(report_data['stats']['severity_breakdown']['low']), 
                 f"{(report_data['stats']['severity_breakdown']['low'] / report_data['total_vulnerabilities'] * 100):.1f}%" if report_data['total_vulnerabilities'] > 0 else "0%"]
            ]
            
            stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1.5*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#007acc')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, HexColor('#dddddd'))
            ]))
            
            story.append(stats_table)
            story.append(Spacer(1, 30))
            
            # Vulnerability details by severity
            severity_colors = {
                'Critical': HexColor('#f44336'),
                'High': HexColor('#ff9800'),
                'Medium': HexColor('#ffeb3b'),
                'Low': HexColor('#4caf50')
            }
            
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                vulnerabilities = report_data['vulnerabilities'].get(severity, [])
                if vulnerabilities:
                    # Severity section header
                    severity_style = ParagraphStyle(
                        f'{severity}Heading',
                        parent=heading_style,
                        textColor=severity_colors[severity]
                    )
                    story.append(Paragraph(f"{severity} Vulnerabilities", severity_style))
                    
                    # Add vulnerabilities
                    for vuln in vulnerabilities:
                        # Vulnerability title
                        story.append(Paragraph(f"<b>{vuln['title']}</b>", styles['Normal']))
                        
                        # Description
                        story.append(Paragraph(vuln['description'], styles['Normal']))
                        
                        # Details table
                        details_data = [
                            ['Category', vuln['priority']['category']],
                            ['Priority Score', f"{vuln['priority']['priority_score']:.2f}/1.0"],
                            ['Impact', vuln['impact'][:100] + "..." if len(vuln['impact']) > 100 else vuln['impact']]
                        ]
                        
                        details_table = Table(details_data, colWidths=[1.5*inch, 4*inch])
                        details_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8f9fa')),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('GRID', (0, 0), (-1, -1), 1, HexColor('#dddddd'))
                        ]))
                        
                        story.append(details_table)
                        
                        # Recommendation
                        story.append(Paragraph("<b>Recommendation:</b>", styles['Normal']))
                        story.append(Paragraph(vuln['recommendation'], styles['Normal']))
                        
                        story.append(Spacer(1, 15))
            
            # Build PDF
            doc.build(story)
            
            logger.info(f"PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise ReportGenerationError(f"PDF report generation failed: {e}")
    
    def generate_json_report(self, 
                           report_data: Dict[str, Any],
                           output_filename: str = None) -> str:
        """
        Generate JSON security report
        
        Args:
            report_data (Dict[str, Any]): Report data
            output_filename (str): Output file name (auto-generated if None)
            
        Returns:
            str: Path to generated JSON report
        """
        logger.info("Generating JSON security report")
        
        try:
            # Generate output filename if not provided
            if not output_filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                app_name = report_data['app_name'].replace(' ', '_')
                output_filename = f"security_report_{app_name}_{timestamp}.json"
            
            output_path = os.path.join(self.output_dir, output_filename)
            
            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"JSON report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            raise ReportGenerationError(f"JSON report generation failed: {e}")
    
    def generate_all_reports(self, 
                           app_info: Dict[str, Any],
                           categorized_vulnerabilities: Dict[str, List[VulnerabilityAnalysis]],
                           executive_summary: str,
                           scan_stats: Dict[str, Any],
                           countermeasures: Dict[str, Any] = None,
                           formats: List[str] = None) -> Dict[str, str]:
        """
        Generate reports in multiple formats
        
        Args:
            app_info (Dict[str, Any]): Application metadata
            categorized_vulnerabilities (Dict[str, List[VulnerabilityAnalysis]]): Categorized vulnerabilities
            executive_summary (str): Executive summary text
            scan_stats (Dict[str, Any]): Scan statistics
            countermeasures (Dict[str, Any]): AI-generated countermeasures and action plan
            formats (List[str]): Report formats to generate ('html', 'pdf', 'json')
            
        Returns:
            Dict[str, str]: Mapping of format to generated file path
        """
        if formats is None:
            formats = ['html', 'pdf', 'json']
        
        logger.info(f"Generating reports in formats: {formats}")
        
        # Prepare report data
        report_data = self.generate_report_data(
            app_info,
            categorized_vulnerabilities,
            executive_summary,
            scan_stats,
            countermeasures
        )
        
        generated_reports = {}
        
        # Generate each requested format
        for report_format in formats:
            try:
                if report_format.lower() == 'html':
                    path = self.generate_html_report(report_data)
                    generated_reports['html'] = path
                elif report_format.lower() == 'pdf':
                    path = self.generate_pdf_report(report_data)
                    generated_reports['pdf'] = path
                elif report_format.lower() == 'json':
                    path = self.generate_json_report(report_data)
                    generated_reports['json'] = path
                else:
                    logger.warning(f"Unsupported report format: {report_format}")
            except Exception as e:
                logger.error(f"Failed to generate {report_format} report: {e}")
                continue
        
        logger.info(f"Generated {len(generated_reports)} reports: {list(generated_reports.keys())}")
        return generated_reports
    
    def get_report_summary(self, report_path: str) -> Dict[str, Any]:
        """
        Get summary information about a generated report
        
        Args:
            report_path (str): Path to the report file
            
        Returns:
            Dict[str, Any]: Report summary information
        """
        try:
            file_path = Path(report_path)
            file_stats = file_path.stat()
            
            summary = {
                'file_path': str(file_path),
                'file_name': file_path.name,
                'file_size': file_stats.st_size,
                'file_size_mb': round(file_stats.st_size / (1024 * 1024), 2),
                'created_time': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                'modified_time': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                'format': file_path.suffix.lower().lstrip('.'),
                'exists': file_path.exists()
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get report summary for {report_path}: {e}")
            return {'error': str(e)}


def create_report_generator(template_dir: str = None, output_dir: str = None) -> SecurityReportGenerator:
    """
    Factory function to create report generator with environment variable fallback
    
    Args:
        template_dir (str): Template directory (uses REPORT_TEMPLATE_DIR env var if None)
        output_dir (str): Output directory (uses REPORT_OUTPUT_DIR env var if None)
        
    Returns:
        SecurityReportGenerator: Configured report generator instance
    """
    template_dir = template_dir or os.getenv('REPORT_TEMPLATE_DIR', './templates')
    output_dir = output_dir or os.getenv('REPORT_OUTPUT_DIR', './reports')
    
    return SecurityReportGenerator(template_dir, output_dir)