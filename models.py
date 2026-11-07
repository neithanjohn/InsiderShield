from datetime import datetime, timedelta, timezone

# IST timezone (UTC+5:30) — duplicated here to avoid circular imports
_IST = timezone(timedelta(hours=5, minutes=30))


def _now_ist():
    return datetime.now(_IST).replace(tzinfo=None)
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Employee(UserMixin, db.Model):
    """Employee Table: Basic profiles and departmental data."""
    __tablename__ = 'employees'

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), nullable=False, default='employee')
    clearance_level = db.Column(db.String(20), default='standard')
    is_admin = db.Column(db.Boolean, default=False)
    is_active_employee = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=_now_ist)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationships
    activities = db.relationship('ActivityLog', backref='employee', lazy='dynamic')
    threats = db.relationship('ThreatDetection', backref='employee', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Employee, self).__init__(**kwargs)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'employee_id': self.employee_id,
            'username': self.username,
            'full_name': self.full_name,
            'email': self.email,
            'department': self.department,
            'role': self.role,
            'clearance_level': self.clearance_level,
            'is_active_employee': self.is_active_employee,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class ActivityLog(db.Model):
    """Activity_Log Table: Detailed records of every session event."""
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    session_id = db.Column(db.String(64), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # login, logout, file_access, file_download, sensitive_file
    action_detail = db.Column(db.String(256), nullable=True)
    file_name = db.Column(db.String(256), nullable=True)
    file_sensitivity = db.Column(db.String(20), default='normal')  # normal, confidential, top_secret
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, default=_now_ist)
    is_weekend = db.Column(db.Boolean, default=False)
    hour_of_day = db.Column(db.Integer, nullable=True)

    def __init__(self, **kwargs):
        super(ActivityLog, self).__init__(**kwargs)

    def to_dict(self):
        return {
            'id': self.id,
            'employee_id': self.employee_id,
            'session_id': self.session_id,
            'action_type': self.action_type,
            'action_detail': self.action_detail,
            'file_name': self.file_name,
            'file_sensitivity': self.file_sensitivity,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat(),
            'is_weekend': self.is_weekend,
            'hour_of_day': self.hour_of_day
        }


class ThreatDetection(db.Model):
    """Threat_Detection Table: ML analysis results."""
    __tablename__ = 'threat_detections'

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    anomaly_score = db.Column(db.Float, nullable=False)
    risk_percentage = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)  # low, medium, high
    classification_label = db.Column(db.String(20), nullable=False)  # Normal, Suspicious
    feature_vector = db.Column(db.Text, nullable=True)  # JSON string of features used
    analysis_period_start = db.Column(db.DateTime, nullable=True)
    analysis_period_end = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_now_ist)

    def __init__(self, **kwargs):
        super(ThreatDetection, self).__init__(**kwargs)

    def to_dict(self):
        return {
            'id': self.id,
            'employee_id': self.employee_id,
            'anomaly_score': self.anomaly_score,
            'risk_percentage': self.risk_percentage,
            'risk_level': self.risk_level,
            'classification_label': self.classification_label,
            'feature_vector': self.feature_vector,
            'created_at': self.created_at.isoformat()
        }


class Alert(db.Model):
    """Alert Table: Logs of generated notifications."""
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    threat_detection_id = db.Column(db.Integer, db.ForeignKey('threat_detections.id'), nullable=True)
    alert_type = db.Column(db.String(50), nullable=False)  # anomaly, threshold_breach, pattern
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, nullable=True)
    is_acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_now_ist)

    # Relationships
    employee_ref = db.relationship('Employee', foreign_keys=[employee_id], backref='alerts_received')
    acknowledger = db.relationship('Employee', foreign_keys=[acknowledged_by])
    threat = db.relationship('ThreatDetection', backref='alerts')

    def __init__(self, **kwargs):
        super(Alert, self).__init__(**kwargs)

    def to_dict(self):
        emp = Employee.query.get(self.employee_id)
        return {
            'id': self.id,
            'employee_id': self.employee_id,
            'employee_name': emp.full_name if emp else 'Unknown',
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'risk_score': self.risk_score,
            'is_acknowledged': self.is_acknowledged,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'created_at': self.created_at.isoformat()
        }


class Report(db.Model):
    """Report Table: Administrative report summaries."""
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(50), nullable=False)  # daily, weekly, incident
    title = db.Column(db.String(200), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=True)
    total_activities = db.Column(db.Integer, default=0)
    total_threats = db.Column(db.Integer, default=0)
    total_alerts = db.Column(db.Integer, default=0)
    high_risk_count = db.Column(db.Integer, default=0)
    medium_risk_count = db.Column(db.Integer, default=0)
    low_risk_count = db.Column(db.Integer, default=0)
    period_start = db.Column(db.DateTime, nullable=True)
    period_end = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=_now_ist)

    generator = db.relationship('Employee', backref='reports_generated')

    def __init__(self, **kwargs):
        super(Report, self).__init__(**kwargs)

    def to_dict(self):
        return {
            'id': self.id,
            'report_type': self.report_type,
            'title': self.title,
            'summary': self.summary,
            'total_activities': self.total_activities,
            'total_threats': self.total_threats,
            'total_alerts': self.total_alerts,
            'high_risk_count': self.high_risk_count,
            'medium_risk_count': self.medium_risk_count,
            'low_risk_count': self.low_risk_count,
            'created_at': self.created_at.isoformat()
        }
