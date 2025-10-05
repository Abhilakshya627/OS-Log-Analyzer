#!/usr/bin/env python3
"""
Integrated Threat and ML Analysis Example
==========================================

This example demonstrates how to use both rule-based threat detection
and machine learning analysis together for comprehensive log security analysis.

Usage:
python integrated_analysis.py <dataset_path>
"""

import sys
import json
from datetime import datetime
from rules import analyze_log_file, print_threat_report
from model import analyze_logs_ml, print_ml_report


def comprehensive_analysis(dataset_path: str):
    """Perform both threat detection and ML analysis."""
    print("🔐 COMPREHENSIVE LOG SECURITY ANALYSIS")
    print("=" * 80)
    print(f"📁 Dataset: {dataset_path}")
    print(f"⏰ Analysis started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 1. Rule-based Threat Detection
    print("PHASE 1: Rule-based Threat Detection")
    print("-" * 40)
    threat_report = analyze_log_file(dataset_path)
    print_threat_report(threat_report)
    
    print("\n" + "=" * 80)
    
    # 2. Machine Learning Analysis  
    print("PHASE 2: Machine Learning Analysis")
    print("-" * 40)
    ml_report = analyze_logs_ml(dataset_path)
    print_ml_report(ml_report)
    
    # 3. Combined Insights
    print("\n" + "=" * 80)
    print("PHASE 3: Combined Security Assessment")
    print("-" * 40)
    
    combined_insights = generate_combined_insights(threat_report, ml_report)
    
    for insight in combined_insights:
        print(f"🔍 {insight}")
    
    # 4. Export comprehensive report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"comprehensive_security_report_{timestamp}.json"
    
    comprehensive_report = {
        'analysis_timestamp': datetime.now().isoformat(),
        'dataset_path': dataset_path,
        'threat_analysis': threat_report,
        'ml_analysis': ml_report,
        'combined_insights': combined_insights
    }
    
    with open(report_file, 'w') as f:
        json.dump(comprehensive_report, f, indent=2, default=str)
    
    print(f"\n💾 Comprehensive report saved to: {report_file}")
    
    return comprehensive_report


def generate_combined_insights(threat_report: dict, ml_report: dict) -> list:
    """Generate insights combining both threat and ML analysis."""
    insights = []
    
    # Check if we have valid reports
    if 'error' in threat_report or 'error' in ml_report:
        insights.append("Analysis incomplete due to errors - check individual reports")
        return insights
    
    # Threat vs ML anomaly correlation
    threat_count = threat_report.get('total_threats_detected', 0)
    ml_anomaly_rate = ml_report.get('anomaly_detection', {}).get('anomaly_rate', 0)
    
    if threat_count > 0 and ml_anomaly_rate > 20:
        insights.append(f"HIGH RISK: Both rule-based threats ({threat_count}) and ML anomalies ({ml_anomaly_rate:.1f}%) detected")
    elif threat_count > 0:
        insights.append(f"MEDIUM RISK: Rule-based threats detected ({threat_count}) but low ML anomaly rate")
    elif ml_anomaly_rate > 30:
        insights.append(f"MEDIUM RISK: High ML anomaly rate ({ml_anomaly_rate:.1f}%) but no rule-based threats")
    else:
        insights.append("LOW RISK: No significant threats or anomalies detected")
    
    # Volume and diversity correlation
    trends = ml_report.get('trend_analysis', {})
    volume_trend = trends.get('log_volume', {}).get('direction', 'stable')
    diversity_trend = trends.get('source_diversity', {}).get('direction', 'stable')
    
    if volume_trend == 'decreasing' and diversity_trend == 'decreasing':
        insights.append("POTENTIAL ISSUE: Both log volume and source diversity decreasing - possible logging system problems")
    elif volume_trend == 'increasing' and ml_anomaly_rate > 25:
        insights.append("MONITORING ALERT: Increasing log volume with high anomaly rate - system under stress")
    
    # Clustering insights for security
    clustering = ml_report.get('clustering', {})
    largest_cluster_pct = 0
    if clustering.get('cluster_summary'):
        largest_cluster_pct = max(c['percentage'] for c in clustering['cluster_summary'])
    
    if largest_cluster_pct > 80:
        insights.append("UNIFORM BEHAVIOR: Very dominant activity pattern - either normal operations or coordinated attack")
    elif largest_cluster_pct < 20:
        insights.append("DIVERSE ACTIVITY: No dominant patterns - either varied legitimate use or reconnaissance")
    
    # Error trend security implications
    error_trend = trends.get('error_rate', {}).get('direction', 'stable')
    if error_trend == 'increasing':
        insights.append("SECURITY CONCERN: Increasing error rate may indicate attack attempts or system compromise")
    
    # Timeline correlation
    threat_timeline = threat_report.get('timeline', [])
    if len(threat_timeline) > 0 and ml_anomaly_rate > 15:
        insights.append("TIME CORRELATION: Threat events coincide with anomalous periods - investigate specific timeframes")
    
    # Recommendations
    if threat_count == 0 and ml_anomaly_rate < 10:
        insights.append("RECOMMENDATION: System appears secure - maintain current monitoring")
    elif threat_count > 5 or ml_anomaly_rate > 40:
        insights.append("RECOMMENDATION: Immediate investigation required - potential security incident")
    else:
        insights.append("RECOMMENDATION: Enhanced monitoring advised - review logs for emerging patterns")
    
    return insights


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python integrated_analysis.py <path_to_excel_dataset>")
        print("Example: python integrated_analysis.py os_logs_dataset_20250926_210947.xlsx")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    comprehensive_analysis(dataset_path)