import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'insidershield-secret-key-2024'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'insidershield.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ML Configuration
    ANOMALY_CONTAMINATION = 0.1  # Expected proportion of outliers
    HIGH_RISK_THRESHOLD = 75
    MEDIUM_RISK_THRESHOLD = 40
    LOW_RISK_THRESHOLD = 0

    # Alert Configuration
    ALERT_THRESHOLD = 60  # Risk score above this triggers alert
