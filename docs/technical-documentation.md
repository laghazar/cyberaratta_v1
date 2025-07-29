# 🛡️ CyberAratta - Technical Documentation

## 📋 Table of Contents
- [System Architecture](#-system-architecture)
- [Technology Stack](#-technology-stack)
- [Database Schema](#-database-schema)
- [API Integrations](#-api-integrations)
- [Security Implementation](#-security-implementation)
- [Performance & Scalability](#-performance--scalability)
- [Deployment Architecture](#-deployment-architecture)
- [Monitoring & Logging](#-monitoring--logging)
- [Development Guidelines](#-development-guidelines)

---

## 🏗️ System Architecture

### Overview
CyberAratta is built using a modular Django architecture with the following core components:

```
CyberAratta/
├── cyberaratta/          # Main project configuration
├── apps/                 # Modular Django applications
│   ├── core/            # Core functionality and utilities
│   ├── url_checker/     # URL security scanning
│   ├── reporting/       # Phishing incident reporting
│   ├── quiz/            # Security awareness training
│   ├── threat_map/      # Geographic threat visualization
│   └── url_email_analyzer/ # Email and URL analysis
├── static/              # Static assets (CSS, JS, Images)
├── templates/           # Django templates
├── media/              # User-uploaded files
└── docs/               # Documentation
```

### Architectural Patterns

#### 1. **Model-View-Template (MVT)**
- **Models**: Data layer with Django ORM
- **Views**: Business logic and request handling
- **Templates**: Presentation layer with Django templating

#### 2. **Modular App Structure**
Each app is self-contained with:
- Models for data persistence
- Views for business logic
- URLs for routing
- Templates for UI
- Static files for app-specific assets

#### 3. **Service Layer Pattern**
- **Utils modules**: Business logic abstraction
- **Service classes**: External API integration
- **Task modules**: Background job processing

---

## 🔧 Technology Stack

### Backend Technologies

| Component | Version | Purpose |
|-----------|---------|---------|
| **Python** | 3.8+ | Core programming language |
| **Django** | 4.2+ | Web framework |
| **Celery** | 5.3+ | Asynchronous task processing |
| **Redis** | 4.6+ | Cache, session store, message broker |
| **SQLite/PostgreSQL** | Latest | Database engine |
| **Gunicorn** | Latest | WSGI HTTP Server |

### Frontend Technologies

| Component | Version | Purpose |
|-----------|---------|---------|
| **Bootstrap** | 4.x | Responsive CSS framework |
| **jQuery** | 3.x | DOM manipulation and AJAX |
| **Chart.js** | Latest | Data visualization |
| **FontAwesome** | 5.x | Icons |
| **Custom CSS** | - | Cyber-themed styling |

### External Integrations

| Service | Purpose | API Version |
|---------|---------|-------------|
| **VirusTotal** | URL/File scanning | v3 |
| **Kaspersky** | Threat detection | v1 |
| **Google Safe Browsing** | URL safety check | v4 |

---

## 🗄️ Database Schema

### Core Models

#### 1. **URL Checker Module**

```python
class URLCheck(models.Model):
    """Primary URL checking model"""
    input_text = CharField(max_length=500)
    status = CharField(choices=['safe', 'suspicious', 'malicious', 'pending'])
    source = CharField(max_length=100)
    analysis_result = TextField()
    checked_at = DateTimeField(auto_now_add=True)
    updated_at = DateTimeField(auto_now=True)

class UrlCheckResult(models.Model):
    """Detailed results from multiple APIs"""
    url_check = ForeignKey(URLCheck)
    virustotal_result = JSONField()
    kaspersky_result = JSONField()
    safebrowsing_result = JSONField()
    checked_at = DateTimeField(auto_now_add=True)

class SecurityIntegration(models.Model):
    """Configurable security API integrations"""
    name = CharField(max_length=100)
    slug = SlugField(unique=True)
    api_url = URLField()
    api_key = CharField(max_length=500)
    status = CharField(choices=['active', 'inactive', 'maintenance'])
    rate_limit_per_minute = PositiveIntegerField(default=60)
    timeout_seconds = PositiveIntegerField(default=30)
```

#### 2. **Reporting Module**

```python
class PhishingReport(models.Model):
    """Phishing incident reports"""
    category = CharField(choices=[
        'banking', 'social_media', 'sms', 'email', 
        'cryptocurrency', 'online_shopping'
    ])
    description = TextField()
    suspicious_url = URLField()
    suspicious_email = EmailField()
    platform_source = ForeignKey(PlatformSource)
    damage_types = ManyToManyField(DamageType)
    evidence_files = JSONField()  # File paths array
    status = CharField(default='pending')
    created_at = DateTimeField(auto_now_add=True)

class DamageType(models.Model):
    """Types of damage from cyber incidents"""
    name = CharField(max_length=300)
    category = CharField(choices=[
        'data_breach', 'financial_loss', 'account_loss',
        'device_control_loss', 'psychological_damage'
    ])
    description = TextField()
    is_active = BooleanField(default=True)
```

#### 3. **Quiz Module**

```python
class QuizCategory(models.Model):
    """Quiz categories for different user types"""
    name = CharField(max_length=100)
    category_type = CharField(choices=[
        'school', 'student', 'professional'
    ])
    professional_field = CharField(choices=[
        'gov', 'bank', 'edu', 'it'
    ])

class Question(models.Model):
    """Security awareness questions"""
    question_text = TextField()
    question_type = CharField(choices=['classic', 'millionaire'])
    category = ForeignKey(QuizCategory)
    difficulty = IntegerField(default=1)
    points = IntegerField(default=10)
    image = ImageField(upload_to='questions/')
    explanation = TextField()

class Answer(models.Model):
    """Question answers"""
    question = ForeignKey(Question)
    answer_text = CharField(max_length=255)
    is_correct = BooleanField(default=False)
```

#### 4. **Threat Map Module**

```python
class Threat(models.Model):
    """Cybersecurity threats for mapping"""
    type = CharField(choices=[
        'phishing', 'malware', 'ddos', 
        'data_breach', 'ransomware'
    ])
    source_country = CharField(max_length=100)
    target_country = CharField(default='Armenia')
    severity = CharField(choices=[
        'low', 'medium', 'high', 'critical'
    ])
    ip_address = GenericIPAddressField()
    reported_at = DateTimeField(auto_now_add=True)

class CyberThreatIntelligence(models.Model):
    """Threat intelligence data"""
    threat_type = CharField(max_length=50)
    source_country = CharField(max_length=100)
    target_sector = CharField(max_length=100)
    confidence_level = CharField(choices=[
        'low', 'medium', 'high'
    ])
    source_feed = CharField(max_length=100)
```

---

## 🔌 API Integrations

### 1. **VirusTotal Integration**

**Configuration:**
```python
# settings.py
VIRUSTOTAL_API_KEY = config('VIRUSTOTAL_API_KEY', default='')
```

**Implementation:**
```python
def check_url_virustotal(url):
    """Check URL against VirusTotal database"""
    api_key = settings.VIRUSTOTAL_API_KEY
    headers = {'x-apikey': api_key}
    
    # Submit URL for analysis
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    response = requests.get(endpoint, headers=headers, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['stats']
        return {
            'status': determine_status(stats),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0)
        }
```

**Rate Limiting:**
- 500 requests per day (free tier)
- 4 requests per minute
- Implemented with Redis-based caching

### 2. **Kaspersky Integration**

**Configuration:**
```python
# settings.py
KASPERSKY_API_KEY = config('KASPERSKY_API_KEY', default='')
```

**Implementation:**
```python
def check_url_kaspersky(url):
    """Check URL against Kaspersky OpenTIP"""
    api_key = settings.KASPERSKY_API_KEY
    headers = {'x-api-key': api_key}
    
    endpoint = f"https://opentip.kaspersky.com/api/v1/scan/url"
    params = {'url': url}
    
    response = requests.get(endpoint, headers=headers, params=params, timeout=30)
    
    if response.status_code == 200:
        data = response.json()
        return {
            'status': data.get('verdict', 'unknown'),
            'confidence': data.get('confidence', 'medium'),
            'categories': data.get('categories', []),
            'zone': data.get('zone', '')
        }
```

### 3. **Google Safe Browsing**

**Configuration:**
```python
# settings.py
GOOGLE_SAFEBROWSING_API_KEY = config('GOOGLE_SAFEBROWSING_API_KEY', default='')
```

**Implementation:**
```python
def check_url_safebrowsing(url):
    """Check URL against Google Safe Browsing"""
    api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "cyberaratta",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    response = requests.post(endpoint, json=payload, timeout=30)
    return response.json()
```

### 4. **Dynamic Integration System**

**Security Integration Model:**
```python
class SecurityIntegration(models.Model):
    """Configurable API integrations"""
    name = CharField(max_length=100, verbose_name="Source Name")
    slug = SlugField(unique=True)
    api_url = URLField()
    api_key = CharField(max_length=500)
    api_headers = JSONField(default=dict)
    status = CharField(choices=[
        ('active', 'Active'),
        ('inactive', 'Inactive'), 
        ('maintenance', 'Maintenance')
    ])
    rate_limit_per_minute = PositiveIntegerField(default=60)
    timeout_seconds = PositiveIntegerField(default=30)
```

**Dynamic Integration Service:**
```python
class IntegrationService:
    """Service for managing dynamic API integrations"""
    
    def get_active_integrations(self):
        return SecurityIntegration.objects.filter(status='active')
    
    def check_url_with_integration(self, integration, url):
        """Check URL using specific integration"""
        try:
            headers = {
                'Authorization': f'Bearer {integration.api_key}',
                **integration.api_headers
            }
            
            response = requests.get(
                integration.api_url,
                headers=headers,
                params={'url': url},
                timeout=integration.timeout_seconds
            )
            
            return self.process_response(integration, response)
            
        except requests.exceptions.Timeout:
            return {'status': 'error', 'message': 'Request timeout'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'message': str(e)}
```

---

## 🔒 Security Implementation

### 1. **Django Security Features**

**CSRF Protection:**
```python
# All forms include CSRF tokens
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ... other middleware
]

# JavaScript CSRF token handling
function getCSRFToken() {
    return document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
}
```

**XSS Prevention:**
```python
# Template auto-escaping enabled by default
# Manual escaping for dynamic content
from django.utils.html import escape, format_html

def format_scan_result(data):
    return format_html(
        '<div class="result">{}</div>',
        escape(data)
    )
```

**SQL Injection Protection:**
```python
# Django ORM prevents SQL injection
URLCheck.objects.filter(input_text=user_input)  # Safe
# Raw SQL with parameterization when needed
cursor.execute("SELECT * FROM table WHERE id = %s", [user_id])
```

### 2. **Authentication & Authorization**

**User Authentication:**
```python
# Django's built-in authentication system
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin

@login_required
def admin_view(request):
    # Only authenticated users
    pass

class AdminView(LoginRequiredMixin, View):
    # Class-based view protection
    pass
```

**Role-Based Access Control:**
```python
from django.contrib.auth.decorators import user_passes_test

def is_admin(user):
    return user.is_staff or user.is_superuser

@user_passes_test(is_admin)
def admin_only_view(request):
    # Admin-only functionality
    pass
```

### 3. **Input Validation & Sanitization**

**URL Validation:**
```python
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
import re

def is_valid_url(url):
    """Validate URL format and safety"""
    validator = URLValidator()
    try:
        validator(url)
        # Additional custom validation
        if re.search(r'[<>"\']', url):
            return False
        return True
    except ValidationError:
        return False
```

**File Upload Security:**
```python
def validate_file_size(value):
    """File size validator"""
    if value.size > 10 * 1024 * 1024:  # 10MB limit
        raise ValidationError('File size cannot exceed 10MB.')

def validate_file_extension(value):
    """File extension validator"""
    allowed_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.txt', '.doc', '.docx']
    ext = os.path.splitext(value.name)[1].lower()
    if ext not in allowed_extensions:
        raise ValidationError('File type not allowed.')

# Model with file validation
class PhishingReport(models.Model):
    evidence_file = models.FileField(
        upload_to='evidence/',
        validators=[validate_file_size, validate_file_extension]
    )
```

### 4. **API Security**

**Rate Limiting:**
```python
from django.core.cache import cache
from django.http import HttpResponseTooManyRequests

def rate_limit_check(request, limit=60, window=60):
    """Simple rate limiting implementation"""
    client_ip = get_client_ip(request)
    key = f"rate_limit:{client_ip}"
    
    current = cache.get(key, 0)
    if current >= limit:
        return HttpResponseTooManyRequests("Rate limit exceeded")
    
    cache.set(key, current + 1, window)
    return None
```

**API Key Management:**
```python
from decouple import config

# Secure API key storage
VIRUSTOTAL_API_KEY = config('VIRUSTOTAL_API_KEY', default='')
KASPERSKY_API_KEY = config('KASPERSKY_API_KEY', default='')

# API key rotation tracking
class APIKeyUsage(models.Model):
    service = CharField(max_length=50)
    requests_count = IntegerField(default=0)
    last_used = DateTimeField(auto_now=True)
    daily_limit = IntegerField(default=1000)
```

**Request/Response Logging:**
```python
import logging

api_logger = logging.getLogger('api_requests')

def log_api_request(service, url, response_code, response_time):
    """Log API requests for monitoring"""
    api_logger.info(
        f"API Request: {service} | URL: {url} | "
        f"Status: {response_code} | Time: {response_time}ms"
    )
```

### 5. **Data Protection**

**Sensitive Data Handling:**
```python
# Environment variables for sensitive data
SECRET_KEY = config('SECRET_KEY', default='your-secret-key-here')
DEBUG = config('DEBUG', default=False, cast=bool)

# Database connection security
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': 'require',
        },
    }
}
```

**Session Security:**
```python
# Secure session configuration
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 3600  # 1 hour
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
```

**Security Headers:**
```python
# Security middleware settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
```

---

## ⚡ Performance & Scalability

### 1. **Caching Strategy**

**Redis Configuration:**
```python
# Cache configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 100,
                'retry_on_timeout': True,
            }
        }
    }
}
```

**Cache Implementation:**
```python
from django.core.cache import cache
from django.views.decorators.cache import cache_page

@cache_page(60 * 15)  # Cache for 15 minutes
def threat_statistics(request):
    """Cached threat statistics"""
    pass

def get_url_check_result(url):
    """Cache URL check results"""
    cache_key = f"url_check:{hashlib.md5(url.encode()).hexdigest()}"
    result = cache.get(cache_key)
    
    if result is None:
        result = perform_url_check(url)
        cache.set(cache_key, result, 3600)  # Cache for 1 hour
    
    return result
```

### 2. **Database Optimization**

**Query Optimization:**
```python
# Use select_related for foreign key queries
reports = PhishingReport.objects.select_related(
    'platform_source'
).prefetch_related('damage_types')

# Database indexing
class URLCheck(models.Model):
    input_text = CharField(max_length=500, db_index=True)
    status = CharField(max_length=20, db_index=True)
    checked_at = DateTimeField(auto_now_add=True, db_index=True)
```

**Connection Pooling:**
```python
# Database connection optimization
DATABASES = {
    'default': {
        # ... other settings
        'CONN_MAX_AGE': 600,  # Connection pooling
        'OPTIONS': {
            'MAX_CONNS': 20,
            'MIN_CONNS': 5,
        }
    }
}
```

### 3. **Asynchronous Processing**

**Celery Configuration:**
```python
# celery.py
from celery import Celery

app = Celery('cyberaratta')
app.config_from_object('django.conf:settings', namespace='CELERY')

# Celery settings
CELERY_BROKER_URL = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Asia/Yerevan'
```

**Background Tasks:**
```python
from celery import shared_task

@shared_task
def analyze_url_background(url_check_id):
    """Background URL analysis task"""
    url_check = URLCheck.objects.get(id=url_check_id)
    
    # Perform time-consuming API calls
    vt_result = check_url_virustotal(url_check.input_text)
    kasp_result = check_url_kaspersky(url_check.input_text)
    
    # Update database
    url_check.analysis_result = format_results(vt_result, kasp_result)
    url_check.status = determine_overall_status(vt_result, kasp_result)
    url_check.save()
    
    return url_check.id

@shared_task
def cleanup_old_records():
    """Periodic cleanup of old data"""
    from datetime import timedelta
    cutoff = timezone.now() - timedelta(days=90)
    
    URLCheck.objects.filter(checked_at__lt=cutoff).delete()
```

### 4. **Static File Optimization**

**Static File Configuration:**
```python
# Static files optimization
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# File size limits
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10MB
```

---

## 🚀 Deployment Architecture

### 1. **Production Environment**

**Server Configuration:**
```nginx
# Nginx configuration
server {
    listen 443 ssl http2;
    server_name cyberaratta.am;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /static/ {
        alias /var/www/cyberaratta/staticfiles/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    location /media/ {
        alias /var/www/cyberaratta/media/;
        expires 1M;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Gunicorn Configuration:**
```python
# gunicorn.conf.py
bind = "127.0.0.1:8000"
workers = 4
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
preload_app = True
timeout = 120
keepalive = 5
```

### 2. **Docker Configuration**

**Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python manage.py collectstatic --noinput
RUN python manage.py migrate

EXPOSE 8000

CMD ["gunicorn", "--config", "gunicorn.conf.py", "cyberaratta.wsgi:application"]
```

**Docker Compose:**
```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=False
      - SECRET_KEY=${SECRET_KEY}
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
    depends_on:
      - db
      - redis

  db:
    image: postgres:14
    environment:
      - POSTGRES_DB=cyberaratta
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  celery:
    build: .
    command: celery -A cyberaratta worker --loglevel=info
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
  redis_data:
```

### 3. **Environment Configuration**

**Production Settings:**
```python
# .env.production
SECRET_KEY=your-super-secure-secret-key
DEBUG=False
ALLOWED_HOSTS=cyberaratta.am,www.cyberaratta.am

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/cyberaratta

# Redis
REDIS_URL=redis://localhost:6379/0

# API Keys
VIRUSTOTAL_API_KEY=your-virustotal-api-key
KASPERSKY_API_KEY=your-kaspersky-api-key
GOOGLE_SAFEBROWSING_API_KEY=your-safebrowsing-api-key

# Security
SECURE_SSL_REDIRECT=True
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True
```

---

## 📊 Monitoring & Logging

### 1. **Logging Configuration**

**Django Logging:**
```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/cyberaratta.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'api_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'logs/api_requests.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'api_requests': {
            'handlers': ['api_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'cyberaratta': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}
```

### 2. **Performance Monitoring**

**Database Query Monitoring:**
```python
# Custom middleware for query monitoring
class QueryCountMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.db import connection
        queries_before = len(connection.queries)
        
        response = self.get_response(request)
        
        queries_after = len(connection.queries)
        query_count = queries_after - queries_before
        
        if query_count > 10:  # Log if too many queries
            logger.warning(f"High query count: {query_count} for {request.path}")
        
        return response
```

**API Response Time Monitoring:**
```python
import time
from functools import wraps

def monitor_api_call(func):
    """Decorator to monitor API call performance"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            status = 'success'
        except Exception as e:
            result = {'error': str(e)}
            status = 'error'
        finally:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            # Log API performance
            api_logger.info(f"API Call: {func.__name__} | "
                          f"Status: {status} | Time: {response_time:.2f}ms")
        
        return result
    return wrapper
```

### 3. **Error Tracking**

**Custom Error Handling:**
```python
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

def handle_api_error(view_func):
    """Decorator for API error handling"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"API Error in {view_func.__name__}: {str(e)}", 
                        exc_info=True)
            return JsonResponse({
                'error': 'Internal server error',
                'message': 'Please try again later'
            }, status=500)
    return wrapper
```

---

## 🛠️ Development Guidelines

### 1. **Code Standards**

**Python Style Guide:**
- Follow PEP 8 conventions
- Use type hints where appropriate
- Maximum line length: 88 characters
- Use meaningful variable and function names

**Django Best Practices:**
- Use Django ORM instead of raw SQL
- Implement proper model validation
- Use Django forms for user input
- Follow Django's security guidelines

### 2. **Testing Strategy**

**Unit Tests:**
```python
from django.test import TestCase
from django.contrib.auth.models import User
from apps.url_checker.models import URLCheck

class URLCheckTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )

    def test_url_check_creation(self):
        """Test URL check model creation"""
        url_check = URLCheck.objects.create(
            input_text='https://example.com',
            status='pending'
        )
        self.assertEqual(url_check.status, 'pending')
        self.assertTrue(url_check.checked_at)

    def test_url_validation(self):
        """Test URL validation function"""
        from apps.url_checker.utils import is_valid_url
        
        self.assertTrue(is_valid_url('https://example.com'))
        self.assertFalse(is_valid_url('invalid-url'))
        self.assertFalse(is_valid_url('javascript:alert(1)'))
```

**Integration Tests:**
```python
from django.test import Client, TestCase
from django.urls import reverse

class URLCheckerIntegrationTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_url_check_endpoint(self):
        """Test URL checking endpoint"""
        response = self.client.post(
            reverse('url_checker:check'),
            {'input_text': 'https://example.com'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('status', data)
        self.assertIn('result', data)
```

### 3. **Security Testing**

**Security Test Cases:**
```python
class SecurityTestCase(TestCase):
    def test_csrf_protection(self):
        """Test CSRF protection on forms"""
        response = self.client.post('/url-checker/', {
            'input_text': 'https://example.com'
        })
        # Should fail without CSRF token
        self.assertEqual(response.status_code, 403)

    def test_input_sanitization(self):
        """Test input sanitization"""
        malicious_input = '<script>alert("xss")</script>'
        response = self.client.post('/url-checker/', {
            'input_text': malicious_input
        })
        # Should handle malicious input safely
        self.assertNotContains(response, '<script>')

    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        malicious_input = "'; DROP TABLE url_checker_urlcheck; --"
        url_check = URLCheck.objects.create(
            input_text=malicious_input,
            status='pending'
        )
        # Should store safely without executing SQL
        self.assertTrue(URLCheck.objects.filter(id=url_check.id).exists())
```

### 4. **Deployment Checklist**

**Pre-deployment:**
- [ ] Run all tests (`python manage.py test`)
- [ ] Check for security issues (`python manage.py check --deploy`)
- [ ] Update requirements.txt
- [ ] Verify environment variables
- [ ] Test database migrations
- [ ] Verify static files collection
- [ ] Check SSL certificates
- [ ] Validate backup procedures

**Post-deployment:**
- [ ] Verify application health
- [ ] Check log files
- [ ] Test critical functionality
- [ ] Monitor performance metrics
- [ ] Verify security headers
- [ ] Test API endpoints
- [ ] Check database connections
- [ ] Validate external integrations

---

## 📝 Conclusion

This technical documentation provides a comprehensive overview of the CyberAratta platform's architecture, security implementation, and development practices. The platform is designed with security, scalability, and maintainability as core principles, ensuring robust protection against cyber threats while providing an intuitive user experience.

For additional information or clarification on any technical aspect, please refer to the specific module documentation or contact the development team.

---

**Last Updated:** July 30, 2025  
**Version:** 1.0  
**Maintainer:** CyberAratta Development Team
