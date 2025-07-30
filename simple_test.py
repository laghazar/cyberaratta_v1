import requests

print("🔍 Ստուգում է API կապը...")
try:
    response = requests.get("http://127.0.0.1:8000/threat_map/api/live-threats/", timeout=5)
    print(f"📡 Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        stats = data.get('statistics', {})
        source = data.get('data_source', 'unknown')
        attacks = data.get('attacks', [])
        
        print("✅ API աշխատում է!")
        print(f"📊 Աղբյուր: {source}")
        print(f"🚨 Հարձակումներ: {len(attacks)}")
        print(f"📈 Ընդամենը: {stats.get('total', 0)}")
        print(f"⚡ Վերջին: {stats.get('recent', 0)}")
        print(f"🌍 Երկրներ: {stats.get('countries', 0)}")
        print(f"🚨 Վտանգի մակարդակ: {stats.get('threat_level', 'unknown')}")
        
        if source == 'real':
            print("🔥 Ստանում եք ԻՐԱԿԱՆ AbuseIPDB տվյալներ!")
        else:
            print("⚠️  Օգտագործվում են demo տվյալներ")
            
    else:
        print(f"❌ Սխալ: {response.status_code}")
        print(response.text)

except Exception as e:
    print(f"❌ Կապի սխալ: {e}")
