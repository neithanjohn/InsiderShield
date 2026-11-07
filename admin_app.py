"""
InsiderShield - Admin Application
Security Administrator Dashboard for threat intelligence.
Runs on port 5001.
"""

import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, Employee, ActivityLog, ThreatDetection, Alert, Report
from shared import run_threat_analysis, now_ist

app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_COOKIE_NAME'] = 'admin_session'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))


# ─── Auth Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Employee.query.filter_by(username=username, is_admin=True).first()
        if user and user.check_password(password):
            login_user(user)
            user.last_login = now_ist()
            session['session_uuid'] = str(uuid.uuid4())
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials or insufficient privileges', 'error')

    return render_template('admin_login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('session_uuid', None)
    return redirect(url_for('login'))


# ─── Dashboard Routes ───────────────────────────────────────────────────────────

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')


@app.route('/api/admin/overview')
@login_required
def admin_overview():
    """Get dashboard overview data."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    total_employees = Employee.query.filter_by(is_admin=False).count()
    total_activities = ActivityLog.query.count()
    total_alerts = Alert.query.filter_by(is_acknowledged=False).count()

    recent_threats = ThreatDetection.query.order_by(
        ThreatDetection.created_at.desc()
    ).limit(20).all()

    high_risk = ThreatDetection.query.filter_by(risk_level='high').count()
    medium_risk = ThreatDetection.query.filter_by(risk_level='medium').count()
    low_risk = ThreatDetection.query.filter_by(risk_level='low').count()

    avg_risk = db.session.query(db.func.avg(ThreatDetection.risk_percentage)).scalar() or 0

    employee_risks = []
    employees = Employee.query.filter_by(is_admin=False).all()
    for emp in employees:
        latest_threat = ThreatDetection.query.filter_by(
            employee_id=emp.id
        ).order_by(ThreatDetection.created_at.desc()).first()

        employee_risks.append({
            'employee': emp.to_dict(),
            'risk_percentage': latest_threat.risk_percentage if latest_threat else 0,
            'risk_level': latest_threat.risk_level if latest_threat else 'low',
            'classification': latest_threat.classification_label if latest_threat else 'Normal',
            'last_analysis': latest_threat.created_at.isoformat() if latest_threat else None
        })

    employee_risks.sort(key=lambda x: x['risk_percentage'], reverse=True)

    return jsonify({
        'total_employees': total_employees,
        'total_activities': total_activities,
        'pending_alerts': total_alerts,
        'average_risk': round(avg_risk, 2),
        'risk_distribution': {
            'high': high_risk,
            'medium': medium_risk,
            'low': low_risk
        },
        'employee_risks': employee_risks,
        'recent_threats': [t.to_dict() for t in recent_threats]
    })


@app.route('/api/admin/alerts')
@login_required
def admin_alerts():
    """Get all alerts."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    alerts = Alert.query.order_by(Alert.created_at.desc()).limit(50).all()
    return jsonify([a.to_dict() for a in alerts])


@app.route('/api/admin/acknowledge_alert/<int:alert_id>', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    alert = Alert.query.get_or_404(alert_id)
    alert.is_acknowledged = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = now_ist()
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Alert acknowledged'})


@app.route('/api/admin/run_analysis', methods=['POST'])
@login_required
def trigger_analysis():
    """Manually trigger threat analysis for all employees."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    results = run_threat_analysis()
    return jsonify({
        'status': 'success',
        'results_count': len(results),
        'results': results
    })


@app.route('/api/admin/employee/<int:employee_id>/activities')
@login_required
def get_employee_activity_detail(employee_id):
    """Get detailed activities for a specific employee."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    activities = ActivityLog.query.filter_by(
        employee_id=employee_id
    ).order_by(ActivityLog.timestamp.desc()).limit(100).all()

    return jsonify([a.to_dict() for a in activities])


@app.route('/api/admin/employee/<int:employee_id>/threats')
@login_required
def get_employee_threats(employee_id):
    """Get threat detections for a specific employee."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    threats = ThreatDetection.query.filter_by(
        employee_id=employee_id
    ).order_by(ThreatDetection.created_at.desc()).limit(20).all()

    return jsonify([t.to_dict() for t in threats])


@app.route('/api/admin/activity_timeline')
@login_required
def activity_timeline():
    """Get activity timeline data for charts."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    now = now_ist()
    start = now - timedelta(hours=24)

    activities = ActivityLog.query.filter(
        ActivityLog.timestamp >= start
    ).all()

    hourly_data = {}
    for a in activities:
        hour_key = a.timestamp.strftime('%H:00')
        if hour_key not in hourly_data:
            hourly_data[hour_key] = {'total': 0, 'file_access': 0, 'file_download': 0, 'sensitive_file': 0}
        hourly_data[hour_key]['total'] += 1
        if a.action_type in hourly_data[hour_key]:
            hourly_data[hour_key][a.action_type] += 1

    return jsonify(hourly_data)


@app.route('/api/admin/generate_report', methods=['POST'])
@login_required
def generate_report():
    """Generate a summary report."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    now = now_ist()
    start = now - timedelta(days=1)

    total_activities = ActivityLog.query.filter(ActivityLog.timestamp >= start).count()
    total_threats = ThreatDetection.query.filter(ThreatDetection.created_at >= start).count()
    total_alerts = Alert.query.filter(Alert.created_at >= start).count()
    high_risk = ThreatDetection.query.filter(
        ThreatDetection.created_at >= start, ThreatDetection.risk_level == 'high'
    ).count()
    medium_risk = ThreatDetection.query.filter(
        ThreatDetection.created_at >= start, ThreatDetection.risk_level == 'medium'
    ).count()
    low_risk = ThreatDetection.query.filter(
        ThreatDetection.created_at >= start, ThreatDetection.risk_level == 'low'
    ).count()

    report = Report(
        report_type='daily',
        title=f'Daily Security Report - {now.strftime("%Y-%m-%d")}',
        summary=f'Generated {total_threats} threat assessments from {total_activities} activities. '
                f'{high_risk} high-risk, {medium_risk} medium-risk, {low_risk} low-risk detections.',
        generated_by=current_user.id,
        total_activities=total_activities,
        total_threats=total_threats,
        total_alerts=total_alerts,
        high_risk_count=high_risk,
        medium_risk_count=medium_risk,
        low_risk_count=low_risk,
        period_start=start,
        period_end=now
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({'status': 'success', 'report': report.to_dict()})


@app.route('/api/admin/reports')
@login_required
def get_reports():
    """Get all reports."""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    reports = Report.query.order_by(Report.created_at.desc()).limit(20).all()
    return jsonify([r.to_dict() for r in reports])


# ─── App Initialization ─────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()
    # Seed only if DB is empty
    from shared import seed_database
    seed_database(app)


if __name__ == '__main__':
    print("=" * 60)
    print("  InsiderShield — Security Admin Dashboard")
    print("  Running on http://127.0.0.1:5001")
    print("=" * 60)
    app.run(debug=True, port=5001)
