from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from shared.models import User


def register_routes(app, login_manager):

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── ROOT ──
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    # ── LOGIN ──
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            user     = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')

        return render_template('login.html')

    # ── LOGOUT ──
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))
# ── MAIN DASHBOARD ──
    @app.route('/dashboard')
    @login_required
    def dashboard():
        from shared.models import Finding, Scan, PostureScore, Repo
        from pipeline.posture_score import get_score_label

        # Get latest completed scan
        latest_scan = Scan.query.filter_by(
            status='completed'
        ).order_by(Scan.started_at.desc()).first()

        # Get findings from latest scan only
        if latest_scan:
            latest_findings = Finding.query.filter_by(
                scan_id=latest_scan.id
            ).filter(
                Finding.confidence_label != 'Low Confidence'
            ).all()
        else:
            latest_findings = []

        # Count by severity from latest scan
        critical_count = sum(
            1 for f in latest_findings
            if f.normalized_severity >= 9.0
        )
        high_count = sum(
            1 for f in latest_findings
            if 7.0 <= f.normalized_severity < 9.0
        )
        medium_count = sum(
            1 for f in latest_findings
            if 4.0 <= f.normalized_severity < 7.0
        )
        low_count = sum(
            1 for f in latest_findings
            if f.normalized_severity < 4.0
        )

        # Total completed scans
        total_scans = Scan.query.filter_by(
            status='completed'
        ).count()

        # Latest posture score
        latest_posture = PostureScore.query.order_by(
            PostureScore.created_at.desc()
        ).first()

        current_score = latest_posture.score \
            if latest_posture else None

        score_label, score_class = get_score_label(
            current_score
        ) if current_score is not None else (
            'No scans yet', 'score-neutral'
        )

        # Previous score for trend arrow
        if latest_posture and latest_posture.previous_score is not None:
            score_change = round(
                current_score - latest_posture.previous_score, 1
            )
        else:
            score_change = None

        # Recent 5 scans for dashboard table
        recent_scans = Scan.query.order_by(
            Scan.started_at.desc()
        ).limit(5).all()

        # Confirmed vs total for latest scan
        confirmed_count = sum(
            1 for f in latest_findings
            if f.confidence_label == 'Confirmed'
        )
        review_count = sum(
            1 for f in latest_findings
            if f.confidence_label == 'Review Needed'
        )

        return render_template(
            'dashboard.html',
            current_score  = current_score,
            score_label    = score_label,
            score_class    = score_class,
            score_change   = score_change,
            critical_count = critical_count,
            high_count     = high_count,
            medium_count   = medium_count,
            low_count      = low_count,
            total_scans    = total_scans,
            recent_scans   = recent_scans,
            confirmed_count = confirmed_count,
            review_count   = review_count,
            latest_scan    = latest_scan,
        )

    # ── SCANS ──
    @app.route('/scans')
    @login_required
    def scans():
        from shared.models import Scan
        scans = Scan.query.order_by(Scan.started_at.desc()).all()
        return render_template('scans.html', scans=scans)

    # ── FINDINGS ──
    @app.route('/findings')
    @login_required
    def findings():
        from shared.models import Finding
        all_findings = Finding.query.order_by(
            Finding.normalized_severity.desc()
        ).all()
        return render_template('findings.html', findings=all_findings)
    

# ── REPOSITORIES ──
# ── REPOSITORIES ──
    @app.route('/repositories')
    @login_required
    def repositories():
        from shared.models import Repo
        repos = Repo.query.order_by(Repo.created_at.desc()).all()
        return render_template('repositories.html', repos=repos)

    # ── REPO CONFIG — VIEW ──
    @app.route('/repositories/<int:repo_id>/config')
    @login_required
    def repo_config(repo_id):
        from shared.models import Repo, RepoConfig
        repo   = Repo.query.get_or_404(repo_id)
        config = RepoConfig.query.filter_by(repo_id=repo_id).first()

        if not config:
            # Create default config if none exists
            from shared.models import db
            config = RepoConfig(
                repo_id      = repo_id,
                run_semgrep  = True,
                run_trivy    = True,
                run_gitleaks = True,
                severity_threshold = 0.0
            )
            db.session.add(config)
            db.session.commit()

        return render_template(
            'repo_config.html',
            repo   = repo,
            config = config
        )

    # ── REPO CONFIG — SAVE ──
    @app.route('/repositories/<int:repo_id>/config/save',
               methods=['POST'])
    @login_required
    def save_repo_config(repo_id):
        from shared.models import db, Repo, RepoConfig
        from flask import jsonify

        repo   = Repo.query.get_or_404(repo_id)
        config = RepoConfig.query.filter_by(repo_id=repo_id).first()

        if not config:
            config = RepoConfig(repo_id=repo_id)
            db.session.add(config)

        # Read form values
        # Checkboxes return 'on' if checked, nothing if unchecked
        config.run_semgrep  = request.form.get('run_semgrep') == 'on'
        config.run_trivy    = request.form.get('run_trivy') == 'on'
        config.run_gitleaks = request.form.get('run_gitleaks') == 'on'

        # Severity threshold — default to 0.0 if invalid
        try:
            threshold = float(request.form.get('severity_threshold', 0.0))
            config.severity_threshold = max(0.0, min(10.0, threshold))
        except (ValueError, TypeError):
            config.severity_threshold = 0.0

        db.session.commit()

        flash(
            f'Configuration saved for {repo.name}',
            'success'
        )
        return redirect(url_for('repo_config', repo_id=repo_id))
    
    # ── POSTURE SCORE ──
    @app.route('/posture')
    @login_required
    def posture():
        from shared.models import PostureScore, Repo
        from pipeline.posture_score import get_score_label

        # Get all posture scores ordered by date
        all_scores = PostureScore.query.order_by(
            PostureScore.created_at.asc()
        ).all()

        # Build chart data
        chart_labels = [
            s.created_at.strftime('%b %d %H:%M')
            for s in all_scores
        ]
        chart_data = [s.score for s in all_scores]

        # Latest score
        latest = all_scores[-1] if all_scores else None
        current_score = latest.score if latest else None
        score_label, score_class = get_score_label(
            current_score
        ) if current_score is not None else ('No scans yet', 'score-neutral')

        return render_template(
            'posture.html',
            all_scores    = all_scores,
            chart_labels  = chart_labels,
            chart_data    = chart_data,
            current_score = current_score,
            score_label   = score_label,
            score_class   = score_class,
        )

    # ── REPORTS ──
    @app.route('/reports')
    @login_required
    def reports():
        from shared.models import Scan
        scans = Scan.query.filter_by(
            status='completed'
        ).order_by(Scan.started_at.desc()).all()
        return render_template('reports.html', scans=scans)
    
    # ── EXPORT CSV ──
    @app.route('/export/csv/<int:scan_id>')
    @login_required
    def export_csv(scan_id):
        """Download scan findings as a CSV file."""
        from flask import Response
        from shared.models import Scan, Finding
        from dashboard.exports import generate_csv

        scan = Scan.query.get_or_404(scan_id)
        findings = Finding.query.filter_by(
            scan_id=scan_id
        ).order_by(Finding.normalized_severity.desc()).all()

        csv_data  = generate_csv(scan, findings)
        filename  = (
            f"devguard_scan_{scan_id}_"
            f"{scan.started_at.strftime('%Y%m%d')}.csv"
            if scan.started_at else f"devguard_scan_{scan_id}.csv"
        )

        return Response(
            csv_data.getvalue(),
            mimetype    = 'text/csv',
            headers     = {
                'Content-Disposition':
                    f'attachment; filename="{filename}"'
            }
        )

    # ── EXPORT PDF ──
    @app.route('/export/pdf/<int:scan_id>')
    @login_required
    def export_pdf(scan_id):
        """Download scan report as a PDF file."""
        from flask import Response
        from shared.models import Scan, Finding, PostureScore
        from dashboard.exports import generate_pdf

        scan = Scan.query.get_or_404(scan_id)
        findings = Finding.query.filter_by(
            scan_id=scan_id
        ).order_by(Finding.normalized_severity.desc()).all()

        posture = PostureScore.query.filter_by(
            scan_id=scan_id
        ).first()

        pdf_data = generate_pdf(scan, findings, posture)
        filename = (
            f"devguard_report_{scan_id}_"
            f"{scan.started_at.strftime('%Y%m%d')}.pdf"
            if scan.started_at else f"devguard_report_{scan_id}.pdf"
        )

        return Response(
            pdf_data.getvalue(),
            mimetype    = 'application/pdf',
            headers     = {
                'Content-Disposition':
                    f'attachment; filename="{filename}"'
            }
        )

    # ── SCAN DETAIL ──
    @app.route('/scans/<int:scan_id>')
    @login_required
    def scan_detail(scan_id):
        """View detailed findings for a specific scan."""
        from shared.models import Scan, Finding, PostureScore
        from pipeline.posture_score import get_score_label

        scan     = Scan.query.get_or_404(scan_id)
        findings = Finding.query.filter_by(
            scan_id=scan_id
        ).order_by(Finding.normalized_severity.desc()).all()

        posture = PostureScore.query.filter_by(
            scan_id=scan_id
        ).first()

        current_score = posture.score if posture else None
        score_label, score_class = get_score_label(
            current_score
        ) if current_score is not None else ('N/A', 'score-neutral')

        critical = sum(1 for f in findings if f.normalized_severity >= 9.0)
        high     = sum(1 for f in findings if 7.0 <= f.normalized_severity < 9.0)
        medium   = sum(1 for f in findings if 4.0 <= f.normalized_severity < 7.0)
        low      = sum(1 for f in findings if f.normalized_severity < 4.0)

        return render_template(
            'scan_detail.html',
            scan          = scan,
            findings      = findings,
            posture       = posture,
            current_score = current_score,
            score_label   = score_label,
            score_class   = score_class,
            critical      = critical,
            high          = high,
            medium        = medium,
            low           = low,
        )