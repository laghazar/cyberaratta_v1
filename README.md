# 🛡️ CyberAratta - Հայաստանի Կիբեռանվտանգության Պլատֆորմ

[![Django](https://img.shields.io/badge/Django-5.2.4-green.svg)](https://djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Demo](https://img.shields.io/badge/Demo-Ready-brightgreen.svg)](#demo)

**CyberAratta**-ն Հայաստանի առաջին ամբողջական կիբեռանվտանգության պլատֆորմն է, որը նախագծված է ֆիշինգ հարձակումների հայտնաբերման, զեկուցման և կիբեռանվտանգության գիտակցության բարձրացման համար:

## 🌟 Հիմնական Հնարավորություններ

### 🔍 URL Ստուգում
- **Իրական ժամանակի սկանավորում** - VirusTotal, Google Safe Browsing API-ների ինտեգրացիա
- **Բազմաշերտ վերլուծություն** - URL, դոմեն, IP հասցե ստուգում
- **Ավտոմատ վտանգավորության գնահատում** - Անվտանգ/Կասկածելի/Վտանգավոր դասակարգում
- **Մանրամասն զեկույցներ** - Տեխնիկական վերլուծություն և առաջարկություններ

### 📊 Ֆիշինգ Զեկուցում
- **Բազմակարգ ֆորմատներ** - SMS, էլ. փոստ, սոցիալական ցանցեր
- **Ֆայլերի վերբեռնում** - Ապացույցների և sceenshot-երի պահպանում
- **Վնասի գնահատում** - Ֆինանսական, տվյալների, հոգեբանական վնաս
- **Արտակարգ կապեր** - Ընդլայնված կոնտակտային տվյալներ ՝ ում դիմել ՀՀ-ում ֆիշինգի զոհ դառնալու դեպքում

### 🗺️ Սպառնալիքների Քարտեզ
- **Հայաստանի ինտերակտիվ քարտեզ** - Leaflet.js տեխնոլոգիայով
- **Իրական ժամանակի թարմացումներ** - WebSocket կապ
- **Գեոլոկացիոն վերլուծություն** - Սպառնալիքների աշխարհագրական բաշխում
- **Տեսողական վիճակագրություն** - Անիմացիոն հաշվիչներ

### 🧠 Կիբեռանվտանգության Քուիզ
- **Բազմաբանական հարցեր** - Ֆիշինգ հայտնաբերում, ուսուցողական բովանդակություն
- **Դժվարության մակարդակներ** - Սկսնակից մինչև փորձագետ
- **Կերպարային արդյունքներ** - Արա Գեղեցիկ / Շամիրամ անհատականություններ
- **Առաջընթացի հետևում** - Մանրամասն վիճակագրություն

### 📧 URL-Email Վերլուծիչ
- **Էլ. փոստի վերլուծություն** - Հեդերների և բովանդակության ստուգում
- **Linkների ստուգում** - Ներկառուցված URL սկանավորում
- **Spam հայտնաբերում** - Ավտոմատ զտում և դասակարգում

## 🏗️ Տեխնիկական Ճարտարապետություն

### Backend
- **Django 5.2.4** - Բազային web framework
- **Python 3.13** - Ծրագրավորման լեզու
- **SQLite3** - Տվյալների բազա (PostgreSQL-ի համար պատրաստ)
- **Celery** - Ասինխրոն առաջադրանքներ
- **Redis** - Cache և message broker

### Frontend
- **Bootstrap 5.3** - Responsive UI framework
- **jQuery 3.7** - JavaScript library
- **Leaflet.js** - Ինտերակտիվ քարտեզներ
- **Chart.js** - Տվյալների վիզուալիզացիա
- **CSS Grid/Flexbox** - Ադապտիվ դիզայն

### API Ինտեգրացիաներ
- **VirusTotal API v3** - Մալվեր հայտնաբերում
- **Google Safe Browsing** - Վտանգավոր կայքերի ստուգում
- **Kaspersky API** - Լրացուցիչ անվտանգության ստուգումներ
- **WhoisAPI** - Դոմեն տեղեկություններ

## 🚀 Տեղադրում և Կարգավորում

### Նախապայմաններ
```bash
Python 3.9+
Node.js 16+ (ոչ պարտադիր)
Git
```

### Արագ տեղադրում

1. **Կլոնավորել repository-ն**
   ```bash
   git clone https://github.com/laghazar/cyberaratta_v1.git
   cd cyberaratta_v1
   ```

2. **Վիրտուալ միջավայր ստեղծել**
   ```bash
   # Windows
   python -m venv .venv
   .venv\Scripts\activate

   # Linux/macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Կախվածությունները տեղադրել**
   ```bash
   pip install -r requirements.txt
   ```

4. **Տվյալների բազան կարգավորել**
   ```bash
   python manage.py migrate
   python manage.py collectstatic --noinput
   ```

5. **Դեմո տվյալներ ավելացնել**
   ```bash
   python populate_demo_data.py
   ```

6. **Սերվերը գործարկել**
   ```bash
   python manage.py runserver 8000
   ```

7. **Բացել բրաուզերում**
   ```
   http://127.0.0.1:8000/
   ```

### Արտադրական միջավայր

#### Environment Variables
```bash
# .env
DEBUG=False
SECRET_KEY=your_secret_key_here
ALLOWED_HOSTS=yourdomain.com

# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key
KASPERSKY_API_KEY=your_kaspersky_api_key

# Database (PostgreSQL)
DATABASE_URL=postgresql://user:pass@localhost:5432/cyberaratta

# Cache (Redis)
REDIS_URL=redis://localhost:6379/0
```

#### Docker Deployment
```bash
# Docker Compose
docker-compose up -d

# Kubernetes
kubectl apply -f k8s/
```

## 📱 Մոդուլների Նկարագրություն

### 🎯 Core Module
**Ուղի:** `/apps/core/`
- Հիմնական մոդելներ և utilities
- Կերպարներ (Արա Գեղեցիկ, Շամիրամ)
- Կայքի վիճակագրություն
- API endpoints

### 🔍 URL Checker Module  
**Ուղի:** `/apps/url_checker/`
- URL սկանավորման engine
- Բազմաշերտ անվտանգության ստուգում
- API ինտեգրացիաներ
- Արդյունքների վիզուալիզացիա

### 📊 Reporting Module
**Ուղի:** `/apps/reporting/`
- Ֆիշինգ զեկուցումների կառավարում
- Ֆայլերի վերբեռնում և պահպանում
- Կոնտակտային տվյալներ
- Վնասի տեսակների դասակարգում

### 🗺️ Threat Map Module
**Ուղի:** `/apps/threat_map/`
- Հայաստանի ինտերակտիվ քարտեզ
- Սպառնալիքների գեոլոկացիա
- Իրական ժամանակի թարմացումներ
- Կիբեռ սպառնալիքների intelligence

### 🧠 Quiz Module
**Ուղի:** `/apps/quiz/`
- Կիբեռանվտանգության հարցումներ
- Դժվարության մակարդակներ
- Կատեգորիաների կառավարում
- Առաջընթացի հետևում

### 📧 URL-Email Analyzer Module
**Ուղի:** `/apps/url_email_analyzer/`
- Էլ. փոստի վերլուծություն
- Header parsing
- Link extraction և ստուգում
- Spam detection

## 🎮 Դեմո և Օգտագործում

### Դեմո
Պլատֆորմն ունի ամբողջական դեմո ռեժիմ, որը ներառում է:

- **200+ ֆիշինգ զեկուցումներ**
- **400+ URL ստուգումներ**
- **300+ սպառնալիքների գրառումներ**
- **15+ քուիզ հարցեր**
- **Իրական ժամանակի վիճակագրություն**

### API Documentation

#### Իրական ժամանակի վիճակագրություն
```bash
GET /threat_map/api/demo/stats/
{
  "total_reports": 200,
  "total_urls_checked": 400,
  "total_threats": 300,
  "quiz_completions": 45
}
```

#### Սպառնալիքների feed
```bash
GET /threat_map/api/demo/threats/
[
  {
    "id": 1,
    "type": "phishing",
    "severity": "high",
    "location": "Yerevan",
    "reported_at": "2025-07-29T10:30:00Z"
  }
]
```

## 🔧 Արդիականացում և Մշակում

### Կանոնական տեստեր
```bash
# Unit tests
python manage.py test

# Coverage հաշվետվություն
coverage run --source='.' manage.py test
coverage html
```

### Code Quality
```bash
# Linting
flake8 apps/
black apps/

# Security check
bandit -r apps/
```

### Performance Monitoring
```bash
# Django Debug Toolbar
pip install django-debug-toolbar

# Database queries optimization
python manage.py check --deploy
```

## 🤝 Ներդրում և Համագործակցություն

### Contribution Guidelines
1. Fork repository-ն
2. Ստեղծել feature branch (`git checkout -b feature/amazing-feature`)
3. Commit փոփոխությունները (`git commit -m 'Add amazing feature'`)
4. Push branch (`git push origin feature/amazing-feature`)
5. Բացել Pull Request

### Issue Reporting
- Բուգերի զեկուցում GitHub Issues-ի միջոցով
- Feature requests-ներ և բարելավումներ
- Անվտանգության հարցեր՝ անձնական հաղորդագրությամբ

## 📄 Լիցենզիա

Այս նախագիծը լիցենզավորված է MIT License-ի ներքո: Մանրամասների համար տես [LICENSE](LICENSE) ֆայլը:

## 🏆 Հեղինակներ 
Larisa Ghazaryan, Seda Asatryan, Hayk Poghosyam, Meri Movsesyan
[Laghazar](https://github.com/laghazar)

Հարցերի առկայության դեպքում կարող եք կապ հաստատել larissaghazaryan@gmail.com էլ․ հասցեով։


---

### 🇦🇲 Ստեղծված է Հայաստանում՝ աշխարհի կիբեռանվտանգության համար

**CyberAratta** - "Տեխնոլոգիական Արա Գեղեցիկ"
