from sklearn.ensemble import IsolationForest
import pandas as pd
import numpy as np

class AnomalyDetector:
    def __init__(self):
        # Isolation Forest is excellent for anomaly detection in logs
        self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        self.is_trained = False

    def train(self, logs):
        """
        Trains the model on a batch of logs.
        Features: Severity (mapped), Status Code, IP Octet deviation.
        """
        if not logs: return
        
        df = pd.DataFrame(logs)
        features = self._preprocess(df)
        
        self.model.fit(features)
        self.is_trained = True

    def predict(self, log):
        """
        Returns -1 for Anomaly, 1 for Normal
        """
        if not self.is_trained:
            return 1 # Assume normal if untrained
            
        df = pd.DataFrame([log])
        features = self._preprocess(df)
        return self.model.predict(features)[0]

    def _preprocess(self, df):
        # Simple feature engineering for the demo
        # Map Severity to int
        sev_map = {"INFO": 0, "WARNING": 5, "CRITICAL": 10}
        df['sev_score'] = df['severity'].map(sev_map).fillna(0)
        
        # Use last octet of IP as a feature (simple heuristic)
        df['ip_last'] = df['source_ip'].apply(lambda x: int(x.split('.')[-1]) if x else 0)
        
        return df[['sev_score', 'status_code', 'ip_last']]

# Singleton instance
detector = AnomalyDetector()