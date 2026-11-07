"""
InsiderShield - Shared utilities for both Employee and Admin applications.
Contains database initialization, seeding, and common helpers.
"""

import uuid
import random
from datetime import datetime, timedelta, timezone
from flask import session, request
from models import db, Employee, ActivityLog, ThreatDetection, Alert
from ml_engine import threat_analyzer

# IST timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))


def now_ist():
    """Return the current time in IST."""
    return datetime.now(IST).replace(tzinfo=None)


def init_db(app):
    """Initialize database with the given Flask app."""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        seed_database(app)


def log_activity(employee_id, action_type, action_detail=None, file_name=None,
                 file_sensitivity='normal', session_id=None):
    """Log an employee activity to the database."""
    now = now_ist()
    activity = ActivityLog(  # type: ignore
        employee_id=employee_id,
        session_id=session_id or session.get('session_uuid', str(uuid.uuid4())),
        action_type=action_type,
        action_detail=action_detail,
        file_name=file_name,
        file_sensitivity=file_sensitivity,
        ip_address=request.remote_addr,
        timestamp=now,
        is_weekend=now.weekday() >= 5,
        hour_of_day=now.hour
    )
    db.session.add(activity)
    db.session.commit()
    return activity


def run_threat_analysis(employee_id=None):
    """Run ML-based threat analysis on employee activities."""
    query = ActivityLog.query
    if employee_id:
        query = query.filter_by(employee_id=employee_id)

    activities = query.order_by(ActivityLog.timestamp.desc()).limit(500).all()

    if not activities:
        return []

    features_df = threat_analyzer.extract_features(activities, employee_id)

    if features_df is None or features_df.empty:
        return []

    if not threat_analyzer.is_fitted:
        all_activities = ActivityLog.query.all()
        all_features = threat_analyzer.extract_features(all_activities)
        if all_features is not None and len(all_features) >= 5:
            threat_analyzer.train(all_features)

    results = threat_analyzer.predict(features_df)

    stored_results = []
    for result in results:
        from flask import current_app
        detection = ThreatDetection(  # type: ignore
            employee_id=result['employee_id'],
            anomaly_score=result['anomaly_score'],
            risk_percentage=result['risk_percentage'],
            risk_level=result['risk_level'],
            classification_label=result['classification_label'],
            feature_vector=result['feature_vector'],
            created_at=now_ist()
        )
        db.session.add(detection)
        db.session.flush()

        if result['risk_percentage'] >= current_app.config.get('ALERT_THRESHOLD', 60):
            emp = Employee.query.get(result['employee_id'])
            alert = Alert(  # type: ignore
                employee_id=result['employee_id'],
                threat_detection_id=detection.id,
                alert_type='anomaly',
                severity='critical' if result['risk_percentage'] >= 90 else
                         'high' if result['risk_percentage'] >= 75 else 'medium',
                title=f"Anomalous behavior detected for {emp.full_name if emp else 'Unknown'}",
                description=f"Risk score: {result['risk_percentage']}%. "
                           f"Classification: {result['classification_label']}. "
                           f"Multiple behavioral indicators triggered.",
                risk_score=result['risk_percentage']
            )
            db.session.add(alert)

        stored_results.append(result)

    db.session.commit()
    return stored_results


def get_simulated_files():
    """Return simulated file system for employee portal."""
    return [
        {'name': 'Q4_Revenue_Report.xlsx', 'type': 'spreadsheet', 'sensitivity': 'normal', 'size': '2.4 MB', 'department': 'Finance'},
        {'name': 'Employee_Handbook.pdf', 'type': 'document', 'sensitivity': 'normal', 'size': '1.1 MB', 'department': 'HR'},
        {'name': 'Project_Timeline.docx', 'type': 'document', 'sensitivity': 'normal', 'size': '340 KB', 'department': 'Operations'},
        {'name': 'Marketing_Strategy_2024.pptx', 'type': 'presentation', 'sensitivity': 'normal', 'size': '5.6 MB', 'department': 'Marketing'},
        {'name': 'Customer_Database_Export.csv', 'type': 'data', 'sensitivity': 'confidential', 'size': '15.2 MB', 'department': 'Sales'},
        {'name': 'Network_Architecture.vsd', 'type': 'diagram', 'sensitivity': 'confidential', 'size': '890 KB', 'department': 'IT'},
        {'name': 'Salary_Structure_2024.xlsx', 'type': 'spreadsheet', 'sensitivity': 'top_secret', 'size': '1.8 MB', 'department': 'HR'},
        {'name': 'Merger_Plans_Draft.pdf', 'type': 'document', 'sensitivity': 'top_secret', 'size': '3.2 MB', 'department': 'Executive'},
        {'name': 'Source_Code_Backup.zip', 'type': 'archive', 'sensitivity': 'top_secret', 'size': '45.0 MB', 'department': 'Engineering'},
        {'name': 'Access_Credentials.txt', 'type': 'text', 'sensitivity': 'top_secret', 'size': '12 KB', 'department': 'IT Security'},
        {'name': 'Meeting_Notes_Jan.docx', 'type': 'document', 'sensitivity': 'normal', 'size': '45 KB', 'department': 'Operations'},
        {'name': 'Vendor_Contracts.pdf', 'type': 'document', 'sensitivity': 'confidential', 'size': '8.4 MB', 'department': 'Legal'},
    ]


def seed_database(app):
    """Seed the database with initial employee data."""
    if Employee.query.first():
        return

    admin = Employee(  # type: ignore
        employee_id='ADM001',
        username='admin',
        full_name='Security Administrator',
        email='admin@insidershield.com',
        department='Security Operations',
        role='Security Admin',
        clearance_level='top_secret',
        is_admin=True
    )
    admin.set_password('admin123')

    employees_data = [
        ('EMP001', 'jsmith', 'John Smith', 'jsmith@company.com', 'Engineering', 'Software Developer', 'standard'),
        ('EMP002', 'agarcia', 'Anna Garcia', 'agarcia@company.com', 'Finance', 'Financial Analyst', 'standard'),
        ('EMP003', 'mwilson', 'Michael Wilson', 'mwilson@company.com', 'HR', 'HR Manager', 'confidential'),
        ('EMP004', 'sjohnson', 'Sarah Johnson', 'sjohnson@company.com', 'Marketing', 'Marketing Lead', 'standard'),
        ('EMP005', 'dlee', 'David Lee', 'dlee@company.com', 'IT', 'System Administrator', 'top_secret'),
        ('EMP006', 'rbrown', 'Rachel Brown', 'rbrown@company.com', 'Sales', 'Sales Executive', 'standard'),
        ('EMP007', 'tchen', 'Thomas Chen', 'tchen@company.com', 'Engineering', 'Senior Developer', 'confidential'),
        ('EMP008', 'kpatel', 'Kavya Patel', 'kpatel@company.com', 'Legal', 'Legal Counsel', 'confidential'),
    ]

    db.session.add(admin)

    for emp_data in employees_data:
        emp = Employee(  # type: ignore
            employee_id=emp_data[0],
            username=emp_data[1],
            full_name=emp_data[2],
            email=emp_data[3],
            department=emp_data[4],
            role=emp_data[5],
            clearance_level=emp_data[6]
        )
        emp.set_password('password123')
        db.session.add(emp)

    db.session.commit()

    # Generate sample activities
    _generate_sample_activities(app)


def _generate_sample_activities(app):
    """Generate sample activities for ML model training."""
    employees = Employee.query.filter_by(is_admin=False).all()
    files = get_simulated_files()
    action_types = ['login', 'logout', 'file_access', 'file_download', 'sensitive_file']
    now = now_ist()

    for emp in employees:
        num_activities = random.randint(20, 40)
        for _ in range(num_activities):
            days_ago = random.randint(0, 6)
            hour = random.choices(
                range(24),
                weights=[1,1,1,1,1,2,3,8,10,10,10,8,7,8,10,10,9,7,4,3,2,1,1,1],
                k=1
            )[0]
            ts = now - timedelta(days=days_ago, hours=random.randint(0, 23) - hour,
                                 minutes=random.randint(0, 59))

            action = random.choices(action_types, weights=[15, 10, 40, 25, 10], k=1)[0]
            file = random.choice(files)
            sensitivity = file['sensitivity'] if action in ['file_access', 'file_download', 'sensitive_file'] else 'normal'

            if action == 'sensitive_file':
                sensitive_files = [f for f in files if f['sensitivity'] in ['confidential', 'top_secret']]
                file = random.choice(sensitive_files) if sensitive_files else file
                sensitivity = file['sensitivity']

            activity = ActivityLog(  # type: ignore
                employee_id=emp.id,
                session_id=str(uuid.uuid4()),
                action_type=action,
                action_detail=f'{action.replace("_", " ").title()} - {file["name"]}',
                file_name=file['name'] if action not in ('login', 'logout') else None,
                file_sensitivity=sensitivity,
                ip_address=f'192.168.1.{random.randint(10, 200)}',
                timestamp=ts,
                is_weekend=ts.weekday() >= 5,
                hour_of_day=ts.hour
            )
            db.session.add(activity)

    # Make one employee look suspicious
    suspect = employees[4] if len(employees) > 4 else employees[0]
    for _ in range(15):
        ts = now - timedelta(days=random.randint(0, 2), hours=random.randint(0, 3))
        sensitive_files = [f for f in files if f['sensitivity'] == 'top_secret']
        file = random.choice(sensitive_files)

        activity = ActivityLog(  # type: ignore
            employee_id=suspect.id,
            session_id=str(uuid.uuid4()),
            action_type='sensitive_file',
            action_detail=f'Accessed Top Secret: {file["name"]}',
            file_name=file['name'],
            file_sensitivity='top_secret',
            ip_address=f'192.168.1.{random.randint(10, 200)}',
            timestamp=ts,
            is_weekend=True,
            hour_of_day=random.choice([1, 2, 3, 23, 0])
        )
        db.session.add(activity)

    db.session.commit()

    with app.app_context():
        run_threat_analysis()
