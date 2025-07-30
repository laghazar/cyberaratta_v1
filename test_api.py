#!/usr/bin/env python3
"""
Test script to verify AbuseIPDB API integration
"""
import requests
from decouple import config

def test_abuseipdb_api():
    """Test AbuseIPDB API connection and functionality"""
    try:
        api_key = config('ABUSEIPDB_API_KEY')
        print(f"🔑 API Key loaded: {api_key[:20]}...")
        
        url = 'https://api.abuseipdb.com/api/v2/blacklist'
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'confidenceMinimum': 90,
            'limit': 5
        }

        print("🌐 Testing AbuseIPDB API connection...")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            malicious_ips = data.get('data', [])
            print(f"✅ AbuseIPDB API working! Found {len(malicious_ips)} malicious IPs")
            
            for i, ip_data in enumerate(malicious_ips[:3], 1):
                ip_address = ip_data.get('ipAddress', 'Unknown')
                country_code = ip_data.get('countryCode', 'Unknown')
                confidence = ip_data.get('confidencePercentage', 0)
                print(f"   {i}. 🚨 {ip_address}: {country_code} (Confidence: {confidence}%)")
            
            return True
        else:
            print(f"❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Connection Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔧 Testing CyberAratta Live Threat Intelligence Integration")
    print("=" * 60)
    
    success = test_abuseipdb_api()
    
    print("=" * 60)
    if success:
        print("🎉 API integration successful! Your threat map will now show live data.")
        print("🌍 Visit your threat map to see real-time cyber threats.")
    else:
        print("⚠️  API test failed. Check your API key and internet connection.")
