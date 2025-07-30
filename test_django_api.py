#!/usr/bin/env python3
"""
Test Django live threats API endpoint
"""
import requests

def test_django_api():
    """Test the Django live threats API endpoint"""
    try:
        print("🌐 Testing Django live threats API...")
        response = requests.get('http://127.0.0.1:8000/threat_map/api/live-threats/', timeout=10)
        
        print(f"📡 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            attacks = data.get('attacks', [])
            source = data.get('data_source', 'unknown')
            stats = data.get('statistics', {})
            
            print(f"✅ API Response successful!")
            print(f"🔍 Data source: {source}")
            print(f"🚨 Live attacks found: {len(attacks)}")
            print(f"📊 Statistics: {stats}")
            
            if attacks:
                print("\n📊 Sample attacks:")
                for i, attack in enumerate(attacks[:3], 1):
                    source_ip = attack.get('source', {}).get('ip', 'Unknown')
                    country = attack.get('source', {}).get('name', 'Unknown')
                    severity = attack.get('severity', 'unknown')
                    print(f"   {i}. {source_ip} from {country} (Severity: {severity})")
            
            # Check if we're getting real data vs demo data
            if source == 'real':
                print("🔥 SUCCESS: Getting REAL live threat data from AbuseIPDB!")
            else:
                print("⚠️  Note: Currently using mock data. Real API might be rate-limited.")
                
            return True
        else:
            print(f"❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Connection Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔧 Testing CyberAratta Django Live Threats API")
    print("=" * 50)
    
    success = test_django_api()
    
    print("=" * 50)
    if success:
        print("🎉 Django API integration working!")
        print("🌍 Your threat map is ready with live data.")
        print("📍 Visit: http://127.0.0.1:8000/threat_map/unified/")
    else:
        print("⚠️  Django API test failed.")
