"""
InsiderShield - Employee Application
Simulated Employee Portal for data generation.
Runs on port 5000.
"""

import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, Employee, ActivityLog
from shared import init_db, log_activity, run_threat_analysis, get_simulated_files, now_ist

app = Flask(__name__)
app.config.from_object(Config)
app.config['SESSION_COOKIE_NAME'] = 'employee_session'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Employee.query.get(int(user_id))


# ─── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('employee_portal'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = Employee.query.filter_by(username=username, is_admin=False).first()
        if user and user.check_password(password):
            login_user(user)
            user.last_login = now_ist()
            session['session_uuid'] = str(uuid.uuid4())
            db.session.commit()

            log_activity(user.id, 'login', f'User logged in from {request.remote_addr}')
            return redirect(url_for('employee_portal'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('employee_login.html')


@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout', 'User logged out')
    logout_user()
    session.pop('session_uuid', None)
    return redirect(url_for('login'))


@app.route('/employee')
@login_required
def employee_portal():
    recent_activities = ActivityLog.query.filter_by(
        employee_id=current_user.id
    ).order_by(ActivityLog.timestamp.desc()).limit(20).all()

    files = get_simulated_files()
    return render_template('employee_portal.html', activities=recent_activities, files=files)


@app.route('/api/employee/action', methods=['POST'])
@login_required
def employee_action():
    """Handle employee actions (file access, download, sensitive file interaction)."""
    data = request.json
    action_type = data.get('action_type')
    file_name = data.get('file_name')
    file_sensitivity = data.get('file_sensitivity', 'normal')
    detail = data.get('detail', '')

    if action_type not in ['file_access', 'file_download', 'sensitive_file']:
        return jsonify({'error': 'Invalid action type'}), 400

    activity = log_activity(
        employee_id=current_user.id,
        action_type=action_type,
        action_detail=detail,
        file_name=file_name,
        file_sensitivity=file_sensitivity
    )

    run_threat_analysis(current_user.id)

    return jsonify({
        'status': 'success',
        'activity': activity.to_dict(),
        'message': f'Action "{action_type}" logged successfully'
    })


@app.route('/api/employee/activities')
@login_required
def get_employee_activities():
    """Get activities for the current employee."""
    activities = ActivityLog.query.filter_by(
        employee_id=current_user.id
    ).order_by(ActivityLog.timestamp.desc()).limit(50).all()

    return jsonify([a.to_dict() for a in activities])


# ─── App Initialization ─────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()
    # Seed only if DB is empty
    from shared import seed_database
    seed_database(app)


if __name__ == '__main__':
    print("=" * 60)
    print("  InsiderShield — Employee Portal")
    print("  Running on http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)
