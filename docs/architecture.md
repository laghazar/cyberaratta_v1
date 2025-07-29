# CyberAratta - High Level Architecture

## System Architecture Overview

```mermaid
graph TB
    subgraph "Client Layer"
        U1[👤 End Users<br/>Citizens & Organizations]
        U2[👨‍💼 System Administrators]
        U3[📱 Mobile Devices]
        U4[💻 Desktop Browsers]
    end

    subgraph "Load Balancing & CDN"
        LB[⚖️ Load Balancer<br/>Nginx]
        CDN[🌐 CDN<br/>Static Assets]
    end

    subgraph "Web Application Layer"
        WS[🌐 Web Server<br/>Nginx + Gunicorn]
        
        subgraph "Django Application"
            CORE[🛡️ CyberAratta Core<br/>Django 5.2.4]
            
            subgraph "Application Modules"
                URLC[🔍 URL Checker<br/>Security Scanning]
                REP[📊 Reporting<br/>Phishing Reports]
                TMAP[🗺️ Threat Map<br/>Geographic Threats]
                QUIZ[🧠 Quiz System<br/>Security Education]
                EMAIL[📧 Email Analyzer<br/>Email Security]
                COREMOD[⚙️ Core Module<br/>Base Functionality]
            end
        end
    end

    subgraph "Background Processing"
        CELERY[⚡ Celery Workers<br/>Async Task Processing]
        BEAT[⏰ Celery Beat<br/>Scheduled Tasks]
    end

    subgraph "Data Layer"
        DB[(🗄️ Primary Database<br/>PostgreSQL)]
        CACHE[(⚡ Cache Layer<br/>Redis)]
        MEDIA[(📁 Media Storage<br/>File System / S3)]
    end

    subgraph "External Security APIs"
        VT[🛡️ VirusTotal<br/>Malware Detection]
        GSB[🔒 Google Safe Browsing<br/>Malicious URL Detection]
        KASP[🦠 Kaspersky<br/>Security Analysis]
        WHOIS[🌍 WhoisAPI<br/>Domain Information]
    end

    subgraph "Monitoring & Analytics"
        MON[📊 Monitoring<br/>Application Health]
        LOG[📝 Logging<br/>System Logs]
        METRICS[📈 Metrics<br/>Performance Data]
    end

    %% User Connections
    U1 --> LB
    U2 --> LB
    U3 --> LB
    U4 --> LB

    %% Load Balancer Connections
    LB --> WS
    LB --> CDN

    %% Web Server Connections
    WS --> CORE
    CDN --> U1
    CDN --> U2
    CDN --> U3
    CDN --> U4

    %% Core Application Connections
    CORE --> URLC
    CORE --> REP
    CORE --> TMAP
    CORE --> QUIZ
    CORE --> EMAIL
    CORE --> COREMOD

    %% Data Connections
    CORE --> DB
    CORE --> CACHE
    CORE --> MEDIA

    %% Background Processing
    CORE --> CELERY
    CELERY --> CACHE
    BEAT --> CELERY

    %% External API Connections
    CELERY --> VT
    CELERY --> GSB
    CELERY --> KASP
    CELERY --> WHOIS

    %% Monitoring Connections
    CORE --> MON
    CORE --> LOG
    MON --> METRICS

    %% Styling
    classDef userLayer fill:#e1f5fe
    classDef webLayer fill:#f3e5f5
    classDef dataLayer fill:#e8f5e8
    classDef externalLayer fill:#fff3e0
    classDef monitoringLayer fill:#fce4ec

    class U1,U2,U3,U4 userLayer
    class LB,CDN,WS,CORE,URLC,REP,TMAP,QUIZ,EMAIL,COREMOD webLayer
    class DB,CACHE,MEDIA dataLayer
    class VT,GSB,KASP,WHOIS externalLayer
    class MON,LOG,METRICS monitoringLayer
```

## Module Architecture Detail

```mermaid
graph LR
    subgraph "Core Module"
        MODELS[📋 Models<br/>SiteStatistics<br/>Characters]
        VIEWS[👁️ Views<br/>Home Dashboard<br/>API Endpoints]
        UTILS[🔧 Utils<br/>Statistics Update<br/>Helper Functions]
    end

    subgraph "URL Checker Module"
        URLM[📋 URL Models<br/>URLCheck<br/>SecurityIntegration]
        URLV[👁️ URL Views<br/>Scan Interface<br/>Results Display]
        URLU[🔧 URL Utils<br/>API Clients<br/>Analyzers]
    end

    subgraph "Reporting Module"
        REPM[📋 Report Models<br/>PhishingReport<br/>ContactInfo]
        REPV[👁️ Report Views<br/>Submit Forms<br/>Admin Interface]
        REPF[📝 Report Forms<br/>File Upload<br/>Validation]
    end

    subgraph "Threat Map Module"
        TMAPM[📋 Threat Models<br/>Threat<br/>ThreatIntelligence]
        TMAPV[👁️ Map Views<br/>Interactive Map<br/>Real-time Updates]
        TMAPJS[🗺️ Map JavaScript<br/>Leaflet.js<br/>WebSocket Client]
    end

    subgraph "Quiz Module"
        QUIZM[📋 Quiz Models<br/>Question<br/>QuizSession]
        QUIZV[👁️ Quiz Views<br/>Question Display<br/>Result Processing]
        QUIZL[🧠 Quiz Logic<br/>Scoring<br/>Character Results]
    end

    subgraph "Email Analyzer Module"
        EMAILM[📋 Email Models<br/>EmailAnalysis<br/>HeaderInfo]
        EMAILV[👁️ Email Views<br/>Upload Interface<br/>Analysis Results]
        EMAILP[🔍 Email Parser<br/>Header Analysis<br/>Link Extraction]
    end

    %% Inter-module connections
    MODELS --> REPM
    MODELS --> TMAPM
    UTILS --> URLV
    UTILS --> REPV
```

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant User
    participant WebServer
    participant Django
    participant Celery
    participant Redis
    participant Database
    participant ExternalAPI

    User->>WebServer: Submit URL for scanning
    WebServer->>Django: Process request
    Django->>Database: Save URL check record
    Django->>Celery: Queue scanning task
    Django->>User: Return immediate response
    
    Celery->>Redis: Get task from queue
    Celery->>ExternalAPI: Call VirusTotal API
    ExternalAPI->>Celery: Return scan results
    Celery->>Database: Update scan results
    Celery->>Redis: Cache results
    
    User->>WebServer: Check scan status
    WebServer->>Django: Get results
    Django->>Redis: Check cache first
    Django->>Database: Fallback to database
    Django->>User: Return scan results
```

## Security Architecture

```mermaid
graph TD
    subgraph "Security Layers"
        WAF[🛡️ Web Application Firewall]
        HTTPS[🔒 HTTPS/TLS Encryption]
        AUTH[🔐 Authentication Layer]
        AUTHZ[✅ Authorization Layer]
        CSRF[🛡️ CSRF Protection]
        XSS[🛡️ XSS Protection]
        SQL[🛡️ SQL Injection Protection]
    end

    subgraph "Input Validation"
        VALID[✅ Input Validation]
        SANIT[🧹 Data Sanitization]
        UPLOAD[📁 File Upload Security]
    end

    subgraph "API Security"
        RATELIMIT[⏱️ Rate Limiting]
        APIKEY[🔑 API Key Management]
        CORS[🌐 CORS Configuration]
    end

    subgraph "Data Protection"
        ENCRYPT[🔒 Data Encryption]
        BACKUP[💾 Secure Backups]
        AUDIT[📋 Audit Logging]
    end

    WAF --> HTTPS
    HTTPS --> AUTH
    AUTH --> AUTHZ
    AUTHZ --> CSRF
    CSRF --> XSS
    XSS --> SQL
    SQL --> VALID
    VALID --> SANIT
    SANIT --> UPLOAD
    UPLOAD --> RATELIMIT
    RATELIMIT --> APIKEY
    APIKEY --> CORS
    CORS --> ENCRYPT
    ENCRYPT --> BACKUP
    BACKUP --> AUDIT
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Production Environment"
        subgraph "Web Tier"
            LB[Load Balancer]
            WEB1[Web Server 1]
            WEB2[Web Server 2]
        end
        
        subgraph "Application Tier"
            APP1[Django App 1]
            APP2[Django App 2]
            WORKER1[Celery Worker 1]
            WORKER2[Celery Worker 2]
        end
        
        subgraph "Data Tier"
            DBMASTER[(Primary DB)]
            DBREPLICA[(Replica DB)]
            REDISMASTER[(Redis Master)]
            REDISSLAVE[(Redis Slave)]
        end
    end

    subgraph "Development Environment"
        DEV[Development Server<br/>SQLite + Redis]
    end

    subgraph "Staging Environment"
        STAGE[Staging Server<br/>PostgreSQL + Redis]
    end

    LB --> WEB1
    LB --> WEB2
    WEB1 --> APP1
    WEB2 --> APP2
    APP1 --> DBMASTER
    APP2 --> DBMASTER
    APP1 --> REDISMASTER
    APP2 --> REDISMASTER
    WORKER1 --> REDISMASTER
    WORKER2 --> REDISMASTER
    DBMASTER --> DBREPLICA
    REDISMASTER --> REDISSLAVE
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Frontend** | Bootstrap 5.3, jQuery, Chart.js, Leaflet.js | Responsive UI, Interactivity, Data Visualization |
| **Backend** | Django 5.2.4, Python 3.13 | Web Framework, Business Logic |
| **Database** | PostgreSQL, SQLite | Data Persistence |
| **Cache** | Redis | Caching, Session Storage, Message Broker |
| **Task Queue** | Celery | Asynchronous Task Processing |
| **Web Server** | Nginx, Gunicorn | HTTP Server, WSGI Server |
| **APIs** | VirusTotal, Google Safe Browsing, Kaspersky | Security Scanning Services |
| **Monitoring** | Django Debug Toolbar, Logging | Performance Monitoring, Error Tracking |

## Performance Considerations

- **Caching Strategy**: Redis for frequently accessed data
- **Database Optimization**: Query optimization, indexing
- **Static File Delivery**: CDN for static assets
- **Asynchronous Processing**: Celery for heavy operations
- **Load Balancing**: Horizontal scaling support
- **Database Replication**: Read replicas for scalability

## Scalability Features

- **Horizontal Scaling**: Multiple web servers and workers
- **Database Sharding**: Potential for data partitioning
- **Microservices Ready**: Modular app structure
- **API-First Design**: RESTful APIs for all functionality
- **Container Ready**: Docker and Kubernetes deployment support
