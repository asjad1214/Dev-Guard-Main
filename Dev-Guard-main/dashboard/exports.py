import csv
import io
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════
# CSV EXPORT
#
# Generates a CSV file containing all findings from a scan.
# Returns a BytesIO object that Flask can send as a download.
# ═══════════════════════════════════════════════════════════

def generate_csv(scan, findings):
    """
    Generate a CSV export for a scan's findings.

    Parameters:
    - scan:     Scan object from the database
    - findings: list of Finding objects for this scan

    Returns:
    - BytesIO object containing the CSV data
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # ── Header row ──
    writer.writerow([
        'Scan ID',
        'Repository',
        'Commit Hash',
        'Scan Date',
        'Tool',
        'Rule ID',
        'File Path',
        'Line Number',
        'Severity (Raw)',
        'Severity (0-10)',
        'Confidence Label',
        'Confidence Score',
        'Message',
    ])

    # ── Data rows ──
    repo_name   = scan.repo.name if scan.repo else 'Unknown'
    scan_date   = scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else ''
    commit_hash = scan.commit_hash[:7] if scan.commit_hash else ''

    for f in findings:
        writer.writerow([
            scan.id,
            repo_name,
            commit_hash,
            scan_date,
            f.tool.upper(),
            f.rule_id or '',
            f.file_path or '',
            f.line_number or '',
            f.raw_severity or '',
            f.normalized_severity or '',
            f.confidence_label or '',
            f.confidence_score or '',
            f.message or '',
        ])

    # Convert to bytes for Flask response
    output.seek(0)
    bytes_output = io.BytesIO()
    bytes_output.write(output.getvalue().encode('utf-8-sig'))
    bytes_output.seek(0)

    logger.info(
        f"[EXPORT] CSV generated for scan {scan.id} "
        f"with {len(findings)} findings"
    )
    return bytes_output


# ═══════════════════════════════════════════════════════════
# PDF EXPORT
#
# Generates a professional PDF report for a scan.
# Uses ReportLab for pure-Python PDF generation.
# ═══════════════════════════════════════════════════════════

def generate_pdf(scan, findings, posture_score=None):
    """
    Generate a professional PDF report for a scan.

    Parameters:
    - scan:          Scan object from the database
    - findings:      list of Finding objects for this scan
    - posture_score: PostureScore object (optional)

    Returns:
    - BytesIO object containing the PDF data
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles   import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units    import cm
    from reportlab.lib           import colors
    from reportlab.platypus      import (
        SimpleDocTemplate, Paragraph, Spacer,
        Table, TableStyle, HRFlowable
    )

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(
        buffer,
        pagesize     = A4,
        rightMargin  = 2*cm,
        leftMargin   = 2*cm,
        topMargin    = 2*cm,
        bottomMargin = 2*cm
    )

    # ── Styles ──
    styles   = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent    = styles['Title'],
        fontSize  = 24,
        textColor = colors.HexColor('#0d1428'),
        spaceAfter = 6,
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent    = styles['Heading2'],
        fontSize  = 13,
        textColor = colors.HexColor('#0d1428'),
        spaceAfter = 6,
        spaceBefore = 12,
    )

    normal_style = ParagraphStyle(
        'CustomNormal',
        parent   = styles['Normal'],
        fontSize = 10,
        textColor = colors.HexColor('#374151'),
    )

    label_style = ParagraphStyle(
        'Label',
        parent    = styles['Normal'],
        fontSize  = 9,
        textColor = colors.HexColor('#6b7280'),
    )

    # ── HEADER ──
    elements.append(
        Paragraph('DevGuard Security Report', title_style)
    )
    elements.append(
        Paragraph(
            'Intelligent DevSecOps Platform — Automated Vulnerability Detection',
            label_style
        )
    )
    elements.append(HRFlowable(width='100%', thickness=1,
                               color=colors.HexColor('#e5e7eb')))
    elements.append(Spacer(1, 0.4*cm))

    # ── SCAN SUMMARY TABLE ──
    elements.append(Paragraph('Scan Summary', heading_style))

    repo_name   = scan.repo.name if scan.repo else 'Unknown'
    scan_date   = scan.started_at.strftime('%Y-%m-%d %H:%M UTC') if scan.started_at else 'N/A'
    commit_hash = scan.commit_hash[:7] if scan.commit_hash else 'N/A'
    score_val   = str(posture_score.score) + '/10' if posture_score else 'N/A'

    summary_data = [
        ['Field', 'Value'],
        ['Repository',     repo_name],
        ['Commit',         commit_hash],
        ['Scan Date',      scan_date],
        ['Status',         scan.status.capitalize()],
        ['Posture Score',  score_val],
        ['Total Findings', str(len(findings))],
    ]

    summary_table = Table(summary_data, colWidths=[5*cm, 12*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR',   (0,0), (-1,0), colors.white),
        ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,0), (-1,0), 10),
        ('BACKGROUND',  (0,1), (0,-1), colors.HexColor('#f8fafc')),
        ('FONTNAME',    (0,1), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE',    (0,1), (-1,-1), 9),
        ('TEXTCOLOR',   (0,1), (-1,-1), colors.HexColor('#374151')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
            [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── SEVERITY BREAKDOWN ──
    elements.append(Paragraph('Severity Breakdown', heading_style))

    critical = sum(1 for f in findings if f.normalized_severity >= 9.0)
    high     = sum(1 for f in findings if 7.0 <= f.normalized_severity < 9.0)
    medium   = sum(1 for f in findings if 4.0 <= f.normalized_severity < 7.0)
    low      = sum(1 for f in findings if f.normalized_severity < 4.0)

    breakdown_data = [
        ['Severity Level', 'Score Range', 'Count'],
        ['Critical',       '9.0 – 10.0', str(critical)],
        ['High',           '7.0 – 8.9',  str(high)],
        ['Medium',         '4.0 – 6.9',  str(medium)],
        ['Low',            '0.1 – 3.9',  str(low)],
    ]

    breakdown_table = Table(breakdown_data, colWidths=[5*cm, 5*cm, 7*cm])
    breakdown_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
        ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,0), 10),
        ('TEXTCOLOR',  (0,1), (-1,1), colors.HexColor('#dc2626')),
        ('TEXTCOLOR',  (0,2), (-1,2), colors.HexColor('#ea580c')),
        ('TEXTCOLOR',  (0,3), (-1,3), colors.HexColor('#ca8a04')),
        ('TEXTCOLOR',  (0,4), (-1,4), colors.HexColor('#16a34a')),
        ('FONTNAME',   (0,1), (-1,-1), 'Helvetica'),
        ('FONTSIZE',   (0,1), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
            [colors.white, colors.HexColor('#f8fafc')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))

    elements.append(breakdown_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── FINDINGS TABLE ──
    if findings:
        elements.append(Paragraph('Findings Detail', heading_style))

        findings_data = [['Tool', 'Severity', 'Confidence', 'File', 'Message']]

        for f in findings:
            sev = f.normalized_severity or 0
            if sev >= 9.0:
                sev_label = f'Critical ({sev})'
            elif sev >= 7.0:
                sev_label = f'High ({sev})'
            elif sev >= 4.0:
                sev_label = f'Medium ({sev})'
            else:
                sev_label = f'Low ({sev})'

            file_path = f.file_path or 'N/A'
            if len(file_path) > 35:
                file_path = '...' + file_path[-32:]

            message = f.message or 'N/A'
            if len(message) > 60:
                message = message[:57] + '...'

            findings_data.append([
                (f.tool or '').upper(),
                sev_label,
                f.confidence_label or 'N/A',
                file_path,
                message,
            ])

        findings_table = Table(
            findings_data,
            colWidths=[2.2*cm, 3*cm, 3*cm, 4*cm, 5*cm]
        )
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR',  (0,0), (-1,0), colors.white),
            ('FONTNAME',   (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,0), 8),
            ('FONTNAME',   (0,1), (-1,-1), 'Helvetica'),
            ('FONTSIZE',   (0,1), (-1,-1), 7),
            ('TEXTCOLOR',  (0,1), (-1,-1), colors.HexColor('#374151')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1),
                [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e5e7eb')),
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('WORDWRAP', (0,0), (-1,-1), True),
        ]))

        elements.append(findings_table)

    # ── FOOTER ──
    elements.append(Spacer(1, 0.8*cm))
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=colors.HexColor('#e5e7eb')
    ))
    elements.append(Spacer(1, 0.2*cm))
    elements.append(Paragraph(
        f'Generated by DevGuard on '
        f'{datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")} | '
        f'Air University FYP 2026',
        label_style
    ))

    # ── Build PDF ──
    doc.build(elements)
    buffer.seek(0)

    logger.info(
        f"[EXPORT] PDF generated for scan {scan.id} "
        f"with {len(findings)} findings"
    )
    return buffer