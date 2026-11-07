"""
InsiderShield ML Engine
Implements Isolation Forest algorithm for anomaly detection in user behavior.
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class ThreatAnalyzer:
    """Core ML engine using Isolation Forest for insider threat detection."""

    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            max_samples='auto'
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def extract_features(self, activities, employee_id=None):
        """
        Feature Engineering: Extract behavioral vectors from activity logs.

        Features:
        - login_hour: Hour of login (temporal pattern)
        - session_duration: Duration of session in minutes
        - file_access_count: Number of file accesses
        - file_download_count: Number of file downloads
        - sensitive_file_count: Number of sensitive file interactions
        - is_weekend: Weekend indicator (environmental context)
        - action_frequency: Actions per hour
        - unique_files_accessed: Number of distinct files
        """
        if not activities:
            return None

        df = pd.DataFrame([a if isinstance(a, dict) else a.to_dict() for a in activities])

        if df.empty:
            return None

        # If filtering for a specific employee
        if employee_id:
            df = df[df['employee_id'] == employee_id]

        if df.empty:
            return None

        # Parse timestamps
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Group by employee for feature extraction
        features_list = []
        employee_ids = df['employee_id'].unique()

        for emp_id in employee_ids:
            emp_df = df[df['employee_id'] == emp_id]

            # Temporal patterns
            login_events = emp_df[emp_df['action_type'] == 'login']
            avg_login_hour = login_events['hour_of_day'].mean() if not login_events.empty else 9.0

            # Session duration estimation (time between first and last action)
            if len(emp_df) > 1:
                session_duration = (emp_df['timestamp'].max() - emp_df['timestamp'].min()).total_seconds() / 60.0
            else:
                session_duration = 0.0

            # Frequency metrics
            file_access_count = len(emp_df[emp_df['action_type'] == 'file_access'])
            file_download_count = len(emp_df[emp_df['action_type'] == 'file_download'])
            sensitive_file_count = len(emp_df[emp_df['action_type'] == 'sensitive_file'])

            # Environmental context
            is_weekend = emp_df['is_weekend'].any()
            weekend_indicator = 1.0 if is_weekend else 0.0

            # Action frequency (actions per hour)
            time_span = max((emp_df['timestamp'].max() - emp_df['timestamp'].min()).total_seconds() / 3600.0, 1.0)
            action_frequency = len(emp_df) / time_span

            # Unique files accessed
            unique_files = emp_df['file_name'].dropna().nunique()

            # Off-hours activity (before 8 AM or after 6 PM)
            off_hours_count = len(emp_df[
                (emp_df['hour_of_day'].notna()) &
                ((emp_df['hour_of_day'] < 8) | (emp_df['hour_of_day'] > 18))
            ])

            feature_vector = {
                'employee_id': emp_id,
                'avg_login_hour': avg_login_hour,
                'session_duration': session_duration,
                'file_access_count': file_access_count,
                'file_download_count': file_download_count,
                'sensitive_file_count': sensitive_file_count,
                'is_weekend': weekend_indicator,
                'action_frequency': action_frequency,
                'unique_files_accessed': unique_files,
                'off_hours_activity': off_hours_count,
                'total_actions': len(emp_df)
            }
            features_list.append(feature_vector)

        return pd.DataFrame(features_list)

    def _get_feature_columns(self):
        """Return the list of feature columns used for ML analysis."""
        return [
            'avg_login_hour', 'session_duration', 'file_access_count',
            'file_download_count', 'sensitive_file_count', 'is_weekend',
            'action_frequency', 'unique_files_accessed', 'off_hours_activity',
            'total_actions'
        ]

    def train(self, features_df):
        """Train the Isolation Forest model on historical behavior data."""
        if features_df is None or features_df.empty:
            return False

        feature_cols = self._get_feature_columns()
        X = features_df[feature_cols].fillna(0).values

        if len(X) < 2:
            return False

        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        return True

    def predict(self, features_df):
        """
        Run anomaly detection on feature vectors.

        Returns:
        - anomaly_scores: Raw anomaly scores from Isolation Forest
        - risk_percentages: Mapped risk percentages (0-100)
        - risk_levels: Categorical risk levels (low, medium, high)
        - classification_labels: Normal or Suspicious
        """
        if features_df is None or features_df.empty:
            return []

        feature_cols = self._get_feature_columns()
        X = features_df[feature_cols].fillna(0).values

        if not self.is_fitted:
            # If model isn't trained, use heuristic scoring
            return self._heuristic_scoring(features_df)

        X_scaled = self.scaler.transform(X)

        # Get anomaly scores (negative = more anomalous)
        raw_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)

        results = []
        for i, (score, pred) in enumerate(zip(raw_scores, predictions)):
            # Map score to 0-100 risk percentage
            # More negative scores = higher risk
            risk_pct = self._score_to_risk_percentage(score)
            risk_level = self._get_risk_level(risk_pct)
            classification = 'Suspicious' if pred == -1 else 'Normal'

            results.append({
                'employee_id': int(features_df.iloc[i]['employee_id']),
                'anomaly_score': float(score),
                'risk_percentage': round(risk_pct, 2),
                'risk_level': risk_level,
                'classification_label': classification,
                'feature_vector': json.dumps({
                    col: float(features_df.iloc[i][col])
                    for col in feature_cols
                })
            })

        return results

    def _heuristic_scoring(self, features_df):
        """Fallback heuristic scoring when model isn't trained."""
        results = []
        feature_cols = self._get_feature_columns()

        for i, row in features_df.iterrows():
            risk_score = 0.0

            # High sensitive file access increases risk
            risk_score += min(row.get('sensitive_file_count', 0) * 15, 40)

            # Excessive downloads increase risk
            risk_score += min(row.get('file_download_count', 0) * 8, 25)

            # Off-hours activity increases risk
            risk_score += min(row.get('off_hours_activity', 0) * 12, 30)

            # Weekend activity increases risk
            if row.get('is_weekend', 0) == 1:
                risk_score += 15

            # Unusual login hours
            login_hour = row.get('avg_login_hour', 9)
            if login_hour < 6 or login_hour > 22:
                risk_score += 20
            elif login_hour < 8 or login_hour > 18:
                risk_score += 10

            # High action frequency
            if row.get('action_frequency', 0) > 10:
                risk_score += 15

            risk_pct = min(risk_score, 100)
            risk_level = self._get_risk_level(risk_pct)
            classification = 'Suspicious' if risk_pct >= 50 else 'Normal'

            results.append({
                'employee_id': int(row['employee_id']),
                'anomaly_score': -risk_pct / 100.0,
                'risk_percentage': round(risk_pct, 2),
                'risk_level': risk_level,
                'classification_label': classification,
                'feature_vector': json.dumps({
                    col: float(row[col])
                    for col in feature_cols
                })
            })

        return results

    def _score_to_risk_percentage(self, score):
        """Convert Isolation Forest score to risk percentage (0-100)."""
        # Isolation Forest scores: positive = normal, negative = anomaly
        # Typical range is roughly -0.5 to 0.5
        # Map to 0-100 where higher = more risky
        risk = (1 - (score + 0.5)) * 100
        return max(0, min(100, risk))

    def _get_risk_level(self, risk_percentage):
        """Map risk percentage to categorical level."""
        if risk_percentage >= 75:
            return 'high'
        elif risk_percentage >= 40:
            return 'medium'
        else:
            return 'low'


# Singleton instance
threat_analyzer = ThreatAnalyzer()
