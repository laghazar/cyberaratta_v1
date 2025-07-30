#!/usr/bin/env python3
"""
Display live threat data in a readable format
"""
import requests
import json
from datetime import datetime

def show_live_threats():
    """Display current live threat data"""
    try:
        print("🌐 Fetching live threat data...")
        response = requests.get('http://127.0.0.1:8000/threat_map/api/live-threats/', timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Display summary
            stats = data.get('statistics', {})
            source = data.get('data_source', 'unknown')
            
            print("=" * 60)
            print("🚨 LIVE CYBER THREAT INTELLIGENCE REPORT")
            print("=" * 60)
            print(f"📊 Data Source: {'🟢 REAL (AbuseIPDB)' if source == 'real' else '🟡 DEMO'}")
            print(f"🔢 Total Threats: {stats.get('total', 0)}")
            print(f"⚡ Recent (5min): {stats.get('recent', 0)}")
            print(f"🌍 Source Countries: {stats.get('countries', 0)}")
            print(f"🚨 Threat Level: {stats.get('threat_level', 'unknown').upper()}")
            print(f"🕐 Last Updated: {data.get('last_updated', 'unknown')}")
            
            # Display individual threats
            attacks = data.get('attacks', [])
            if attacks:
                print("\n🎯 TOP THREAT SOURCES:")
                print("-" * 60)
                for i, attack in enumerate(attacks[:10], 1):
                    source_info = attack.get('source', {})
                    ip = source_info.get('ip', 'Unknown IP')
                    country = source_info.get('name', 'Unknown')
                    coords = source_info.get('coordinates', [0, 0])
                    severity = attack.get('severity', 'unknown')
                    timestamp = attack.get('timestamp', '')
                    
                    # Format timestamp
                    try:
                        dt = datetime.fromisoformat(timestamp)
                        time_str = dt.strftime("%H:%M:%S")
                    except:
                        time_str = "Unknown"
                    
                    severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                    
                    print(f"{i:2d}. {severity_icon} {ip:<15} | {country:<12} | {time_str}")
            
            print("=" * 60)
            print("🌍 View interactive map at: http://127.0.0.1:8000/threat_map/unified/")
            print("=" * 60)
            
        else:
            print(f"❌ API Error: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    show_live_threats()
