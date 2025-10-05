#!/usr/bin/env python3
"""
Unsupervised Machine Learning Models for Log Analysis
=====================================================

This module implements unsupervised machine learning techniques for analyzing
system logs, detecting anomalies, clustering similar events, and identifying
trends and patterns in log data.

Features:
- Anomaly detection using Isolation Forest and One-Class SVM
- Log clustering using K-Means and DBSCAN
- Time series analysis for trend detection
- Feature engineering for log data
- Behavioral pattern analysis
- Automated model training and evaluation
- Visualization of results and patterns

Author: OS Log Analyzer - ML Edition  
Date: October 3, 2025
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import json
import pickle
import warnings
from dataclasses import dataclass
from collections import Counter

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Machine Learning Imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.decomposition import PCA
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import silhouette_score
    
    # Optional imports for enhanced functionality
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
        VISUALIZATION_AVAILABLE = True
    except ImportError:
        VISUALIZATION_AVAILABLE = False
        
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")


# Data Structures
# ===============

@dataclass
class AnomalyResult:
    """Structure for anomaly detection results."""
    timestamp: datetime
    anomaly_score: float
    is_anomaly: bool
    features: Dict[str, float]
    original_log: Dict[str, Any]
    description: str


@dataclass
class ClusterResult:
    """Structure for clustering results."""
    cluster_id: int
    cluster_size: int
    dominant_sources: List[str]
    common_patterns: List[str]
    time_range: Tuple[datetime, datetime]
    representative_logs: List[Dict[str, Any]]


@dataclass
class TrendAnalysis:
    """Structure for trend analysis results."""
    metric_name: str
    trend_direction: str  # 'increasing', 'decreasing', 'stable', 'volatile'
    slope: float
    r_squared: float
    predictions: List[float]
    timestamps: List[datetime]
    anomalous_points: List[int]


# Feature Engineering
# ==================

class LogFeatureExtractor:
    """Extracts numerical features from log entries for ML analysis."""
    
    def __init__(self):
        self.source_encoder = LabelEncoder()
        self.level_encoder = LabelEncoder()
        self.tfidf_vectorizer = TfidfVectorizer(max_features=100, stop_words='english')
        self.is_fitted = False
    
    def extract_basic_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract basic numerical features from log data."""
        features = pd.DataFrame()
        
        # Time-based features
        features['hour'] = df['Timestamp'].dt.hour
        features['day_of_week'] = df['Timestamp'].dt.dayofweek
        features['is_weekend'] = (df['Timestamp'].dt.dayofweek >= 5).astype(int)
        features['is_business_hours'] = ((df['Timestamp'].dt.hour >= 8) & 
                                       (df['Timestamp'].dt.hour <= 17)).astype(int)
        
        # Event ID (if numeric)
        try:
            features['event_id'] = pd.to_numeric(df['Event_ID'], errors='coerce').fillna(0)
        except:
            features['event_id'] = 0
        
        # Message length
        features['message_length'] = df['Message'].str.len()
        features['log_message_words'] = df['Message'].str.split().str.len()
        
        # Source encoding
        if not self.is_fitted:
            try:
                features['source_encoded'] = self.source_encoder.fit_transform(df['Source'])
            except:
                features['source_encoded'] = 0
        else:
            try:
                features['source_encoded'] = self.source_encoder.transform(df['Source'])
            except:
                features['source_encoded'] = 0
        
        # Level encoding
        if not self.is_fitted:
            try:
                features['level_encoded'] = self.level_encoder.fit_transform(df['Level'])
            except:
                features['level_encoded'] = 0
        else:
            try:
                features['level_encoded'] = self.level_encoder.transform(df['Level'])
            except:
                features['level_encoded'] = 0
        
        return features
    
    def extract_text_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract TF-IDF features from log messages."""
        try:
            if not self.is_fitted:
                tfidf_matrix = self.tfidf_vectorizer.fit_transform(df['Message'].fillna(''))
                self.is_fitted = True
            else:
                tfidf_matrix = self.tfidf_vectorizer.transform(df['Message'].fillna(''))
            
            # Convert to DataFrame
            feature_names = [f'tfidf_{i}' for i in range(tfidf_matrix.shape[1])]
            tfidf_features = pd.DataFrame(
                tfidf_matrix.toarray(), 
                columns=feature_names,
                index=df.index
            )
            
            return tfidf_features
        except:
            # Fallback: return empty features
            return pd.DataFrame(index=df.index)
    
    def extract_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract statistical features based on patterns."""
        features = pd.DataFrame()
        
        # Source frequency
        source_counts = df['Source'].value_counts()
        features['source_frequency'] = df['Source'].map(source_counts)
        
        # Level distribution
        level_counts = df['Level'].value_counts()
        features['level_frequency'] = df['Level'].map(level_counts)
        
        # Time intervals (if multiple entries)
        if len(df) > 1:
            df_sorted = df.sort_values('Timestamp')
            time_diffs = df_sorted['Timestamp'].diff().dt.total_seconds().fillna(0)
            features['time_since_last'] = time_diffs.values
        else:
            features['time_since_last'] = 0
        
        return features
    
    def extract_all_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract all available features."""
        basic_features = self.extract_basic_features(df)
        text_features = self.extract_text_features(df)
        stat_features = self.extract_statistical_features(df)
        
        # Combine all features
        all_features = pd.concat([basic_features, text_features, stat_features], axis=1)
        
        # Fill NaN values
        all_features = all_features.fillna(0)
        
        return all_features


# Anomaly Detection Models
# =======================

class LogAnomalyDetector:
    """Detects anomalies in log data using multiple ML techniques."""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        self.one_class_svm = OneClassSVM(nu=0.1)
        self.scaler = StandardScaler()
        self.feature_extractor = LogFeatureExtractor()
        self.is_trained = False
        
    def train(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train anomaly detection models."""
        if not ML_AVAILABLE:
            return {"error": "Machine learning libraries not available"}
        
        print("Training anomaly detection models...")
        
        # Extract features
        features = self.feature_extractor.extract_all_features(df)
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train models
        self.isolation_forest.fit(features_scaled)
        self.one_class_svm.fit(features_scaled)
        
        self.is_trained = True
        
        # Get training statistics
        if_scores = self.isolation_forest.decision_function(features_scaled)
        svm_scores = self.one_class_svm.decision_function(features_scaled)
        
        return {
            "training_samples": len(df),
            "feature_count": features.shape[1],
            "isolation_forest_scores": {
                "mean": float(np.mean(if_scores)),
                "std": float(np.std(if_scores)),
                "min": float(np.min(if_scores)),
                "max": float(np.max(if_scores))
            },
            "svm_scores": {
                "mean": float(np.mean(svm_scores)),
                "std": float(np.std(svm_scores)),
                "min": float(np.min(svm_scores)),
                "max": float(np.max(svm_scores))
            }
        }
    
    def detect_anomalies(self, df: pd.DataFrame) -> List[AnomalyResult]:
        """Detect anomalies in new log data."""
        if not self.is_trained:
            raise ValueError("Model must be trained before detecting anomalies")
        
        # Extract features
        features = self.feature_extractor.extract_all_features(df)
        features_scaled = self.scaler.transform(features)
        
        # Get predictions and scores
        if_predictions = self.isolation_forest.predict(features_scaled)
        if_scores = self.isolation_forest.decision_function(features_scaled)
        
        svm_predictions = self.one_class_svm.predict(features_scaled)
        svm_scores = self.one_class_svm.decision_function(features_scaled)
        
        # Combine results
        anomalies = []
        for i in range(len(df)):
            # Anomaly if either model flags it
            is_anomaly = (if_predictions[i] == -1) or (svm_predictions[i] == -1)
            
            # Combined anomaly score (lower = more anomalous)
            combined_score = (if_scores[i] + svm_scores[i]) / 2
            
            if is_anomaly or combined_score < -0.1:  # Threshold for reporting
                anomalies.append(AnomalyResult(
                    timestamp=df.iloc[i]['Timestamp'],
                    anomaly_score=float(combined_score),
                    is_anomaly=is_anomaly,
                    features=features.iloc[i].to_dict(),
                    original_log=df.iloc[i].to_dict(),
                    description=self._generate_anomaly_description(df.iloc[i], combined_score)
                ))
        
        return anomalies
    
    def _generate_anomaly_description(self, log_entry: pd.Series, score: float) -> str:
        """Generate human-readable description of anomaly."""
        descriptions = []
        
        # Time-based anomalies
        hour = log_entry['Timestamp'].hour
        if hour < 6 or hour > 22:
            descriptions.append("unusual time of day")
        
        # Message-based anomalies
        message_len = len(str(log_entry.get('Message', '')))
        if message_len > 1000:
            descriptions.append("unusually long message")
        elif message_len < 10:
            descriptions.append("unusually short message")
        
        # Source-based anomalies
        source = str(log_entry.get('Source', ''))
        if 'unknown' in source.lower() or len(source) < 3:
            descriptions.append("unusual source")
        
        if not descriptions:
            if score < -0.5:
                descriptions.append("highly anomalous pattern")
            else:
                descriptions.append("anomalous log pattern")
        
        return f"Anomaly detected: {', '.join(descriptions)} (score: {score:.3f})"


# Clustering Models
# ================

class LogClusterAnalyzer:
    """Clusters log entries to identify patterns and group similar events."""
    
    def __init__(self):
        self.kmeans = None
        self.dbscan = None
        self.scaler = StandardScaler()
        self.feature_extractor = LogFeatureExtractor()
        self.pca = PCA(n_components=0.95)  # Retain 95% variance
        
    def perform_clustering(self, df: pd.DataFrame, method: str = 'kmeans', n_clusters: int = 5) -> List[ClusterResult]:
        """Perform clustering analysis on log data."""
        if not ML_AVAILABLE:
            return []
        
        print(f"Performing {method} clustering...")
        
        # Extract and scale features
        features = self.feature_extractor.extract_all_features(df)
        features_scaled = self.scaler.fit_transform(features)
        
        # Reduce dimensionality
        features_reduced = self.pca.fit_transform(features_scaled)
        
        # Perform clustering
        if method == 'kmeans':
            self.kmeans = KMeans(n_clusters=n_clusters, random_state=42)
            cluster_labels = self.kmeans.fit_predict(features_reduced)
        elif method == 'dbscan':
            self.dbscan = DBSCAN(eps=0.5, min_samples=5)
            cluster_labels = self.dbscan.fit_predict(features_reduced)
            n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
        else:
            raise ValueError("Method must be 'kmeans' or 'dbscan'")
        
        # Analyze clusters
        clusters = []
        for cluster_id in set(cluster_labels):
            if cluster_id == -1:  # DBSCAN noise
                continue
                
            cluster_mask = cluster_labels == cluster_id
            cluster_df = df[cluster_mask]
            
            if len(cluster_df) == 0:
                continue
            
            # Analyze cluster characteristics
            dominant_sources = cluster_df['Source'].value_counts().head(3).index.tolist()
            
            # Extract common patterns from messages
            messages = cluster_df['Message'].tolist()
            common_words = self._extract_common_patterns(messages)
            
            # Time range
            time_range = (cluster_df['Timestamp'].min(), cluster_df['Timestamp'].max())
            
            # Representative logs
            representative_logs = cluster_df.head(3).to_dict('records')
            
            clusters.append(ClusterResult(
                cluster_id=int(cluster_id),
                cluster_size=len(cluster_df),
                dominant_sources=dominant_sources,
                common_patterns=common_words,
                time_range=time_range,
                representative_logs=representative_logs
            ))
        
        # Calculate silhouette score if possible
        if len(set(cluster_labels)) > 1:
            silhouette_avg = silhouette_score(features_reduced, cluster_labels)
            print(f"Average silhouette score: {silhouette_avg:.3f}")
        
        return sorted(clusters, key=lambda x: x.cluster_size, reverse=True)
    
    def _extract_common_patterns(self, messages: List[str], top_n: int = 5) -> List[str]:
        """Extract common patterns from log messages."""
        # Simple word frequency analysis
        all_words = []
        for message in messages:
            words = str(message).lower().split()
            # Filter out common uninteresting words
            filtered_words = [
                word for word in words 
                if len(word) > 2 and word not in ['the', 'and', 'for', 'with', 'has', 'was', 'are']
            ]
            all_words.extend(filtered_words)
        
        word_counts = Counter(all_words)
        return [word for word, count in word_counts.most_common(top_n)]
    
    def find_optimal_clusters(self, df: pd.DataFrame, max_clusters: int = 10) -> int:
        """Find optimal number of clusters using elbow method."""
        if not ML_AVAILABLE:
            return 3
        
        features = self.feature_extractor.extract_all_features(df)
        features_scaled = self.scaler.fit_transform(features)
        features_reduced = self.pca.fit_transform(features_scaled)
        
        inertias = []
        K_range = range(2, min(max_clusters + 1, len(df) // 2))
        
        for k in K_range:
            kmeans = KMeans(n_clusters=k, random_state=42)
            kmeans.fit(features_reduced)
            inertias.append(kmeans.inertia_)
        
        # Find elbow point (simplified)
        if len(inertias) >= 2:
            diffs = np.diff(inertias)
            elbow_point = np.argmax(diffs) + 2  # +2 because range starts at 2
            return min(elbow_point, max_clusters)
        
        return 3  # Default fallback


# Trend Analysis
# ==============

class LogTrendAnalyzer:
    """Analyzes trends and patterns in log data over time."""
    
    def analyze_volume_trends(self, df: pd.DataFrame, window: str = '1H') -> TrendAnalysis:
        """Analyze log volume trends over time."""
        # Resample data by time window
        df_resampled = df.set_index('Timestamp').resample(window).size()
        
        # Calculate trend
        x = np.arange(len(df_resampled))
        y = df_resampled.values
        
        if len(y) > 1:
            # Linear regression
            slope, intercept = np.polyfit(x, y, 1)
            predictions = slope * x + intercept
            
            # R-squared
            y_mean = np.mean(y)
            ss_tot = np.sum((y - y_mean) ** 2)
            ss_res = np.sum((y - predictions) ** 2)
            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
            
            # Trend direction
            if abs(slope) < 0.1:
                trend_direction = 'stable'
            elif slope > 0:
                trend_direction = 'increasing'
            else:
                trend_direction = 'decreasing'
            
            # Detect anomalous points (simple method)
            std_dev = np.std(y - predictions)
            anomalous_points = [i for i, val in enumerate(y) if abs(val - predictions[i]) > 2 * std_dev]
            
        else:
            slope, r_squared = 0, 0
            trend_direction = 'stable'
            predictions = y
            anomalous_points = []
        
        return TrendAnalysis(
            metric_name='log_volume',
            trend_direction=trend_direction,
            slope=float(slope),
            r_squared=float(r_squared),
            predictions=predictions.tolist(),
            timestamps=df_resampled.index.tolist(),
            anomalous_points=anomalous_points
        )
    
    def analyze_error_trends(self, df: pd.DataFrame) -> TrendAnalysis:
        """Analyze error rate trends over time."""
        # Filter for error-level logs
        error_df = df[df['Level'].isin(['error', 'critical', 'Error', 'Critical'])]
        
        if len(error_df) == 0:
            return TrendAnalysis(
                metric_name='error_rate',
                trend_direction='stable',
                slope=0.0,
                r_squared=0.0,
                predictions=[],
                timestamps=[],
                anomalous_points=[]
            )
        
        return self.analyze_volume_trends(error_df, window='1H')
    
    def analyze_source_diversity(self, df: pd.DataFrame, window: str = '1H') -> TrendAnalysis:
        """Analyze diversity of log sources over time."""
        # Group by time window and count unique sources
        df_grouped = df.set_index('Timestamp').groupby(pd.Grouper(freq=window))['Source'].nunique()
        
        x = np.arange(len(df_grouped))
        y = df_grouped.values
        
        if len(y) > 1:
            slope, intercept = np.polyfit(x, y, 1)
            predictions = slope * x + intercept
            
            y_mean = np.mean(y)
            ss_tot = np.sum((y - y_mean) ** 2)
            ss_res = np.sum((y - predictions) ** 2)
            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
            
            if abs(slope) < 0.1:
                trend_direction = 'stable'
            elif slope > 0:
                trend_direction = 'increasing'
            else:
                trend_direction = 'decreasing'
        else:
            slope, r_squared = 0, 0
            trend_direction = 'stable'
            predictions = y
        
        return TrendAnalysis(
            metric_name='source_diversity',
            trend_direction=trend_direction,
            slope=float(slope),
            r_squared=float(r_squared),
            predictions=predictions.tolist(),
            timestamps=df_grouped.index.tolist(),
            anomalous_points=[]
        )


# Main Analysis Class
# ==================

class LogMLAnalyzer:
    """Main class combining all ML analysis capabilities."""
    
    def __init__(self):
        self.anomaly_detector = LogAnomalyDetector()
        self.cluster_analyzer = LogClusterAnalyzer()
        self.trend_analyzer = LogTrendAnalyzer()
        
    def full_analysis(self, dataset_path: str) -> Dict[str, Any]:
        """Perform complete ML analysis on dataset."""
        if not ML_AVAILABLE:
            return {"error": "Machine learning libraries not available. Install scikit-learn."}
        
        try:
            # Load dataset
            df = pd.read_excel(dataset_path, sheet_name='Raw_Logs')
            df['Timestamp'] = pd.to_datetime(df['Timestamp'])
            
            print(f"Performing ML analysis on {len(df)} log entries...")
            
            results = {
                'dataset_info': {
                    'total_entries': len(df),
                    'time_range': {
                        'start': df['Timestamp'].min().isoformat(),
                        'end': df['Timestamp'].max().isoformat()
                    },
                    'unique_sources': df['Source'].nunique(),
                    'log_types': df['Log_Type'].unique().tolist()
                }
            }
            
            # 1. Anomaly Detection
            print("🔍 Training anomaly detection models...")
            train_results = self.anomaly_detector.train(df)
            results['training_info'] = train_results
            
            anomalies = self.anomaly_detector.detect_anomalies(df)
            results['anomaly_detection'] = {
                'total_anomalies': len(anomalies),
                'anomaly_rate': len(anomalies) / len(df) * 100,
                'top_anomalies': [
                    {
                        'timestamp': a.timestamp.isoformat(),
                        'score': a.anomaly_score,
                        'description': a.description,
                        'source': a.original_log.get('Source', 'Unknown')
                    }
                    for a in sorted(anomalies, key=lambda x: x.anomaly_score)[:10]
                ]
            }
            
            # 2. Clustering Analysis
            print("🔗 Performing clustering analysis...")
            optimal_clusters = self.cluster_analyzer.find_optimal_clusters(df)
            clusters = self.cluster_analyzer.perform_clustering(df, n_clusters=optimal_clusters)
            
            results['clustering'] = {
                'optimal_clusters': optimal_clusters,
                'clusters_found': len(clusters),
                'cluster_summary': [
                    {
                        'cluster_id': c.cluster_id,
                        'size': c.cluster_size,
                        'percentage': c.cluster_size / len(df) * 100,
                        'dominant_sources': c.dominant_sources,
                        'common_patterns': c.common_patterns,
                        'time_span_hours': (c.time_range[1] - c.time_range[0]).total_seconds() / 3600
                    }
                    for c in clusters
                ]
            }
            
            # 3. Trend Analysis
            print("📈 Analyzing trends...")
            volume_trend = self.trend_analyzer.analyze_volume_trends(df)
            error_trend = self.trend_analyzer.analyze_error_trends(df)
            diversity_trend = self.trend_analyzer.analyze_source_diversity(df)
            
            results['trend_analysis'] = {
                'log_volume': {
                    'direction': volume_trend.trend_direction,
                    'slope': volume_trend.slope,
                    'correlation': volume_trend.r_squared,
                    'anomalous_periods': len(volume_trend.anomalous_points)
                },
                'error_rate': {
                    'direction': error_trend.trend_direction,
                    'slope': error_trend.slope,
                    'correlation': error_trend.r_squared
                },
                'source_diversity': {
                    'direction': diversity_trend.trend_direction,
                    'slope': diversity_trend.slope,
                    'correlation': diversity_trend.r_squared
                }
            }
            
            # 4. Summary Insights
            insights = self._generate_insights(results, anomalies, clusters)
            results['insights'] = insights
            
            return results
            
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def _generate_insights(self, results: Dict, anomalies: List, clusters: List) -> List[str]:
        """Generate human-readable insights from analysis results."""
        insights = []
        
        # Anomaly insights
        if results['anomaly_detection']['anomaly_rate'] > 10:
            insights.append(f"High anomaly rate detected ({results['anomaly_detection']['anomaly_rate']:.1f}%) - system may need investigation")
        elif results['anomaly_detection']['anomaly_rate'] < 1:
            insights.append("Very low anomaly rate - system appears stable")
        
        # Clustering insights
        largest_cluster = max(results['clustering']['cluster_summary'], key=lambda x: x['size']) if clusters else None
        if largest_cluster and largest_cluster['percentage'] > 50:
            insights.append(f"Dominant activity pattern found: {largest_cluster['percentage']:.1f}% of logs from {largest_cluster['dominant_sources'][0] if largest_cluster['dominant_sources'] else 'unknown source'}")
        
        # Trend insights
        volume_trend = results['trend_analysis']['log_volume']
        if volume_trend['direction'] == 'increasing' and volume_trend['slope'] > 0.5:
            insights.append("Log volume is increasing significantly - monitor system resources")
        elif volume_trend['direction'] == 'decreasing':
            insights.append("Log volume is decreasing - verify logging configuration")
        
        error_trend = results['trend_analysis']['error_rate']
        if error_trend['direction'] == 'increasing':
            insights.append("Error rate is increasing - investigate system issues")
        
        if not insights:
            insights.append("System logging patterns appear normal")
        
        return insights
    
    def save_model(self, filepath: str):
        """Save trained models to file."""
        model_data = {
            'anomaly_detector': {
                'isolation_forest': self.anomaly_detector.isolation_forest,
                'one_class_svm': self.anomaly_detector.one_class_svm,
                'scaler': self.anomaly_detector.scaler,
                'feature_extractor': self.anomaly_detector.feature_extractor,
                'is_trained': self.anomaly_detector.is_trained
            }
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self, filepath: str):
        """Load trained models from file."""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        ad_data = model_data['anomaly_detector']
        self.anomaly_detector.isolation_forest = ad_data['isolation_forest']
        self.anomaly_detector.one_class_svm = ad_data['one_class_svm']
        self.anomaly_detector.scaler = ad_data['scaler']
        self.anomaly_detector.feature_extractor = ad_data['feature_extractor']
        self.anomaly_detector.is_trained = ad_data['is_trained']


# Visualization Functions
# ======================

def plot_analysis_results(results: Dict[str, Any], save_path: str = None):
    """Create visualization plots for analysis results."""
    if not VISUALIZATION_AVAILABLE:
        print("Matplotlib not available for visualization")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Log Analysis Results', fontsize=16)
    
    # 1. Anomaly Rate
    ax1 = axes[0, 0]
    anomaly_rate = results.get('anomaly_detection', {}).get('anomaly_rate', 0)
    normal_rate = 100 - anomaly_rate
    ax1.pie([normal_rate, anomaly_rate], labels=['Normal', 'Anomalous'], 
            colors=['lightgreen', 'lightcoral'], autopct='%1.1f%%')
    ax1.set_title('Anomaly Distribution')
    
    # 2. Cluster Sizes
    ax2 = axes[0, 1]
    cluster_data = results.get('clustering', {}).get('cluster_summary', [])
    if cluster_data:
        cluster_sizes = [c['size'] for c in cluster_data[:5]]  # Top 5 clusters
        cluster_labels = [f"Cluster {c['cluster_id']}" for c in cluster_data[:5]]
        ax2.bar(cluster_labels, cluster_sizes, color='lightblue')
        ax2.set_title('Top 5 Cluster Sizes')
        plt.setp(ax2.get_xticklabels(), rotation=45)
    
    # 3. Trend Direction Summary
    ax3 = axes[1, 0]
    trends = results.get('trend_analysis', {})
    trend_metrics = ['log_volume', 'error_rate', 'source_diversity']
    trend_directions = [trends.get(metric, {}).get('direction', 'stable') for metric in trend_metrics]
    
    direction_counts = Counter(trend_directions)
    ax3.bar(direction_counts.keys(), direction_counts.values(), color='lightyellow')
    ax3.set_title('Trend Directions')
    
    # 4. Insights Text
    ax4 = axes[1, 1]
    insights = results.get('insights', ['No insights available'])
    insight_text = '\n'.join([f"• {insight}" for insight in insights[:5]])
    ax4.text(0.1, 0.5, insight_text, fontsize=10, verticalalignment='center', 
             wrap=True, transform=ax4.transAxes)
    ax4.set_title('Key Insights')
    ax4.axis('off')
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Analysis visualization saved to: {save_path}")
    else:
        plt.show()


# Main execution
# ==============

def analyze_logs_ml(dataset_path: str) -> Dict[str, Any]:
    """Main function for ML-based log analysis."""
    analyzer = LogMLAnalyzer()
    return analyzer.full_analysis(dataset_path)


def print_ml_report(results: Dict[str, Any]):
    """Print formatted ML analysis report."""
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print("🤖 MACHINE LEARNING ANALYSIS REPORT")
    print("=" * 60)
    
    # Dataset info
    info = results['dataset_info']
    print(f"📊 Dataset: {info['total_entries']} entries")
    print(f"⏰ Time range: {info['time_range']['start'][:19]} to {info['time_range']['end'][:19]}")
    print(f"🏷️  Unique sources: {info['unique_sources']}")
    
    # Anomaly detection
    anomaly = results['anomaly_detection']
    print(f"\n🔍 Anomaly Detection:")
    print(f"   • Total anomalies: {anomaly['total_anomalies']}")
    print(f"   • Anomaly rate: {anomaly['anomaly_rate']:.2f}%")
    
    if anomaly['top_anomalies']:
        print("   • Top anomalies:")
        for a in anomaly['top_anomalies'][:3]:
            print(f"     - {a['timestamp'][:19]}: {a['description'][:60]}...")
    
    # Clustering
    clustering = results['clustering']
    print(f"\n🔗 Clustering Analysis:")
    print(f"   • Optimal clusters: {clustering['optimal_clusters']}")
    print(f"   • Clusters found: {clustering['clusters_found']}")
    
    if clustering['cluster_summary']:
        print("   • Largest clusters:")
        for c in clustering['cluster_summary'][:3]:
            patterns = ', '.join(c['common_patterns'][:3])
            print(f"     - Cluster {c['cluster_id']}: {c['size']} entries ({c['percentage']:.1f}%) - {patterns}")
    
    # Trend analysis
    trends = results['trend_analysis']
    print(f"\n📈 Trend Analysis:")
    print(f"   • Log volume: {trends['log_volume']['direction']} (R²: {trends['log_volume']['correlation']:.3f})")
    print(f"   • Error rate: {trends['error_rate']['direction']} (R²: {trends['error_rate']['correlation']:.3f})")
    print(f"   • Source diversity: {trends['source_diversity']['direction']} (R²: {trends['source_diversity']['correlation']:.3f})")
    
    # Insights
    print(f"\n💡 Key Insights:")
    for insight in results['insights']:
        print(f"   • {insight}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python model.py <path_to_excel_dataset>")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    
    print("🚀 Starting ML analysis...")
    results = analyze_logs_ml(dataset_path)
    
    print_ml_report(results)
    
    # Save detailed results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"ml_analysis_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    
    # Create visualization if possible
    if VISUALIZATION_AVAILABLE:
        plot_file = f"ml_analysis_plot_{timestamp}.png"
        plot_analysis_results(results, plot_file)