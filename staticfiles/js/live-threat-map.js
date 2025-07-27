// Live Threat Map JavaScript - Armenia Cyber Security Monitor

class LiveThreatMap {
    constructor(containerId) {
        this.containerId = containerId;
        this.map = null;
        this.attackLines = [];
        this.sourceMarkers = [];
        this.armeniaMarker = null;
        this.refreshInterval = null;
        this.refreshTimer = 30;
        
        // Armenia coordinates (Yerevan)
        this.armeniaCoords = [40.1792, 44.4991];
        
        // Map settings
        this.mapSettings = {
            center: this.armeniaCoords,
            zoom: 7,
            minZoom: 5,
            maxZoom: 10
        };
        
        // Attack data
        this.attacks = [];
        this.stats = {
            total: 0,
            recent: 0,
            countries: new Set(),
            threatLevel: 'low'
        };
        
        // Control elements
        this.controls = {
            showAttackLines: true,
            showSourceMarkers: true,
            autoRefresh: true
        };
    }
    
    async initialize() {
        this.showLoading(true);
        
        try {
            // Initialize map
            this.initializeMap();
            
            // Load initial data
            await this.loadThreatData();
            
            // Setup controls
            this.setupControls();
            
            // Start auto refresh
            this.startAutoRefresh();
            
            this.showLoading(false);
            
            console.log('✅ Live Threat Map initialized successfully');
        } catch (error) {
            console.error('❌ Failed to initialize threat map:', error);
            this.showError('Failed to initialize threat map');
        }
    }
    
    initializeMap() {
        // Create map
        this.map = L.map(this.containerId, {
            center: this.mapSettings.center,
            zoom: this.mapSettings.zoom,
            minZoom: this.mapSettings.minZoom,
            maxZoom: this.mapSettings.maxZoom,
            zoomControl: true,
            scrollWheelZoom: true
        });
        
        // Add dark theme tile layer
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(this.map);
        
        // Add Armenia marker
        this.addArmeniaMarker();
        
        // Restrict map bounds to region
        const bounds = L.latLngBounds(
            [38.5, 43.0], // Southwest coordinates
            [41.5, 46.5]  // Northeast coordinates
        );
        this.map.setMaxBounds(bounds);
        
        console.log('🗺️ Map initialized');
    }
    
    addArmeniaMarker() {
        const armeniaIcon = L.divIcon({
            className: 'armenia-marker-custom',
            html: '<div style="width: 20px; height: 20px; background: linear-gradient(45deg, #d90429, #ee6c4d); border: 3px solid #ffffff; border-radius: 50%; box-shadow: 0 0 15px rgba(217, 4, 41, 0.6);"></div>',
            iconSize: [20, 20],
            iconAnchor: [10, 10]
        });
        
        this.armeniaMarker = L.marker(this.armeniaCoords, { 
            icon: armeniaIcon,
            zIndexOffset: 1000
        }).addTo(this.map);
        
        this.armeniaMarker.bindPopup(`
            <div style="text-align: center; color: #333;">
                <h4>🇦🇲 Հայաստանի Հանրապետություն</h4>
                <p><strong>Թիրախ:</strong> Կիբեռ սպառնալիքներ</p>
                <p><strong>Կարգավիճակ:</strong> <span style="color: #d90429;">Պաշտպանված</span></p>
            </div>
        `);
    }
    
    async loadThreatData() {
        try {
            // Simulate loading threat data from multiple sources
            console.log('📡 Loading threat data...');
            
            // In real implementation, this would call:
            // 1. AbuseIPDB API for malicious IPs
            // 2. ipapi.co for geolocation
            // 3. Internal threat intelligence
            
            const mockAttacks = await this.generateMockThreatData();
            this.attacks = mockAttacks;
            
            this.updateStatistics();
            this.renderAttacks();
            this.updateAttackLog();
            
            console.log(`📊 Loaded ${this.attacks.length} threat indicators`);
        } catch (error) {
            console.error('❌ Failed to load threat data:', error);
            throw error;
        }
    }
    
    async generateMockThreatData() {
        // Mock data generator for demonstration
        // In production, replace with real API calls
        
        const sourceCountries = [
            { name: 'Russia', coords: [55.7558, 37.6176], flag: '🇷🇺', threat: 'high' },
            { name: 'China', coords: [39.9042, 116.4074], flag: '🇨🇳', threat: 'medium' },
            { name: 'Iran', coords: [35.6892, 51.3890], flag: '🇮🇷', threat: 'high' },
            { name: 'Turkey', coords: [39.9334, 32.8597], flag: '🇹🇷', threat: 'medium' },
            { name: 'USA', coords: [38.9072, -77.0369], flag: '🇺🇸', threat: 'low' },
            { name: 'Germany', coords: [52.5200, 13.4050], flag: '🇩🇪', threat: 'low' },
            { name: 'North Korea', coords: [39.0392, 125.7625], flag: '🇰🇵', threat: 'high' },
            { name: 'Azerbaijan', coords: [40.4093, 49.8671], flag: '🇦🇿', threat: 'medium' },
            { name: 'Pakistan', coords: [33.6844, 73.0479], flag: '🇵🇰', threat: 'medium' },
            { name: 'Ukraine', coords: [50.4501, 30.5234], flag: '🇺🇦', threat: 'low' }
        ];
        
        const attackTypes = [
            'DDoS Attack', 'Malware Distribution', 'Phishing Campaign',
            'Brute Force', 'SQL Injection', 'Data Breach Attempt',
            'Ransomware', 'APT Activity', 'Bot Network', 'Credential Stuffing',
            'Zero-day Exploit', 'Social Engineering', 'DNS Hijacking'
        ];
        
        const attacks = [];
        const numAttacks = Math.floor(Math.random() * 20) + 15; // 15-35 attacks
        
        for (let i = 0; i < numAttacks; i++) {
            const source = sourceCountries[Math.floor(Math.random() * sourceCountries.length)];
            const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
            const timestamp = new Date(Date.now() - Math.random() * 6 * 60 * 60 * 1000); // Last 6 hours
            
            attacks.push({
                id: `attack_${Date.now()}_${i}`,
                source: source,
                target: { name: 'Armenia', coords: this.armeniaCoords },
                type: attackType,
                timestamp: timestamp,
                severity: source.threat,
                ip: this.generateRandomIP(),
                details: `${attackType} detected from ${source.name}`,
                port: Math.floor(Math.random() * 65535) + 1
            });
        }
        
        return attacks.sort((a, b) => b.timestamp - a.timestamp);
    }
    
    generateRandomIP() {
        return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }
    
    updateStatistics() {
        const now = new Date();
        const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);
        
        this.stats.total = this.attacks.length;
        this.stats.recent = this.attacks.filter(attack => attack.timestamp > fiveMinutesAgo).length;
        this.stats.countries = new Set(this.attacks.map(attack => attack.source.name));
        
        // Determine threat level
        const highThreatAttacks = this.attacks.filter(attack => attack.severity === 'high').length;
        if (highThreatAttacks > 5) {
            this.stats.threatLevel = 'high';
        } else if (highThreatAttacks > 2 || this.stats.recent > 3) {
            this.stats.threatLevel = 'medium';
        } else {
            this.stats.threatLevel = 'low';
        }
        
        this.updateStatsDisplay();
    }
    
    updateStatsDisplay() {
        document.getElementById('totalAttacks').textContent = this.stats.total;
        document.getElementById('recentAttacks').textContent = this.stats.recent;
        document.getElementById('sourceCountries').textContent = this.stats.countries.size;
        
        const threatLevelElement = document.getElementById('threatLevel');
        threatLevelElement.textContent = this.stats.threatLevel.toUpperCase();
        threatLevelElement.className = `threat-level ${this.stats.threatLevel}`;
    }
    
    renderAttacks() {
        this.clearAttacks();
        
        if (this.controls.showSourceMarkers) {
            this.renderSourceMarkers();
        }
        
        if (this.controls.showAttackLines) {
            this.renderAttackLines();
        }
    }
    
    renderSourceMarkers() {
        const sourceCountries = new Map();
        
        // Group attacks by source country
        this.attacks.forEach(attack => {
            const key = attack.source.name;
            if (!sourceCountries.has(key)) {
                sourceCountries.set(key, {
                    ...attack.source,
                    attacks: []
                });
            }
            sourceCountries.get(key).attacks.push(attack);
        });
        
        // Create markers for each source country
        sourceCountries.forEach((country, name) => {
            const severity = this.getMostSevereThreat(country.attacks);
            const color = severity === 'high' ? '#ff4757' : 
                         severity === 'medium' ? '#ffa502' : '#ff6b6b';
            
            const markerIcon = L.divIcon({
                className: 'custom-source-marker',
                html: `<div style="
                    width: 16px; 
                    height: 16px; 
                    background: ${color}; 
                    border: 2px solid #ffffff; 
                    border-radius: 50%; 
                    box-shadow: 0 0 10px ${color}80;
                    animation: markerPulse 2s infinite;
                "></div>`,
                iconSize: [16, 16],
                iconAnchor: [8, 8]
            });
            
            const marker = L.marker(country.coords, { icon: markerIcon })
                .addTo(this.map);
            
            const popupContent = `
                <div style="color: #333; min-width: 200px;">
                    <h4>${country.flag} ${country.name}</h4>
                    <p><strong>Հարձակումներ:</strong> ${country.attacks.length}</p>
                    <p><strong>Վտանգավորություն:</strong> <span style="color: ${color};">${severity.toUpperCase()}</span></p>
                    <hr>
                    <div style="max-height: 100px; overflow-y: auto;">
                        ${country.attacks.slice(0, 3).map(attack => 
                            `<div style="margin-bottom: 5px; font-size: 12px;">
                                ${attack.type} - ${attack.timestamp.toLocaleTimeString()}
                            </div>`
                        ).join('')}
                    </div>
                </div>
            `;
            
            marker.bindPopup(popupContent);
            this.sourceMarkers.push(marker);
        });
    }
    
    renderAttackLines() {
        this.attacks.forEach((attack, index) => {
            // Create animated line from source to Armenia
            setTimeout(() => {
                this.createAttackLine(attack);
            }, index * 200); // Stagger animations
        });
    }
    
    createAttackLine(attack) {
        const color = attack.severity === 'high' ? '#ff4757' : 
                     attack.severity === 'medium' ? '#ffa502' : '#00ff88';
        
        const line = L.polyline([attack.source.coords, attack.target.coords], {
            color: color,
            weight: 2,
            opacity: 0.7,
            dashArray: '10, 5',
            className: 'attack-line-animated'
        }).addTo(this.map);
        
        // Add popup to line
        line.bindPopup(`
            <div style="color: #333;">
                <h4>🚨 Կիբեռ հարձակում</h4>
                <p><strong>Աղբյուր:</strong> ${attack.source.flag} ${attack.source.name}</p>
                <p><strong>Տեսակ:</strong> ${attack.type}</p>
                <p><strong>IP:</strong> ${attack.ip}</p>
                <p><strong>Ժամ:</strong> ${attack.timestamp.toLocaleString()}</p>
                <p><strong>Վտանգավորություն:</strong> <span style="color: ${color};">${attack.severity.toUpperCase()}</span></p>
            </div>
        `);
        
        this.attackLines.push(line);
        
        // Remove line after animation (optional)
        setTimeout(() => {
            if (line && this.map) {
                this.map.removeLayer(line);
                const index = this.attackLines.indexOf(line);
                if (index > -1) {
                    this.attackLines.splice(index, 1);
                }
            }
        }, 10000); // Remove after 10 seconds
    }
    
    getMostSevereThreat(attacks) {
        if (attacks.some(a => a.severity === 'high')) return 'high';
        if (attacks.some(a => a.severity === 'medium')) return 'medium';
        return 'low';
    }
    
    clearAttacks() {
        // Clear attack lines
        this.attackLines.forEach(line => {
            if (this.map.hasLayer(line)) {
                this.map.removeLayer(line);
            }
        });
        this.attackLines = [];
        
        // Clear source markers
        this.sourceMarkers.forEach(marker => {
            if (this.map.hasLayer(marker)) {
                this.map.removeLayer(marker);
            }
        });
        this.sourceMarkers = [];
    }
    
    updateAttackLog() {
        const logContainer = document.getElementById('attackLogContainer');
        const recentAttacks = this.attacks.slice(0, 10); // Show last 10 attacks
        
        if (recentAttacks.length === 0) {
            logContainer.innerHTML = '<div class="log-item">📡 Հարձակումներ չեն հայտնաբերվել</div>';
            return;
        }
        
        const logHTML = recentAttacks.map(attack => {
            const timeStr = attack.timestamp.toLocaleTimeString();
            const severity = attack.severity === 'high' ? '🔴' : 
                           attack.severity === 'medium' ? '🟠' : '🟡';
            
            return `
                <div class="log-item">
                    <span class="log-time">${timeStr}</span>
                    <span class="log-source">${severity} ${attack.source.flag} ${attack.source.name}</span>
                    <span class="log-details">${attack.type} (${attack.ip})</span>
                </div>
            `;
        }).join('');
        
        logContainer.innerHTML = logHTML;
    }
    
    setupControls() {
        // Attack lines toggle
        document.getElementById('showAttackLines').addEventListener('change', (e) => {
            this.controls.showAttackLines = e.target.checked;
            this.renderAttacks();
        });
        
        // Source markers toggle
        document.getElementById('showSourceMarkers').addEventListener('change', (e) => {
            this.controls.showSourceMarkers = e.target.checked;
            this.renderAttacks();
        });
        
        // Auto refresh toggle
        document.getElementById('autoRefresh').addEventListener('change', (e) => {
            this.controls.autoRefresh = e.target.checked;
            if (e.target.checked) {
                this.startAutoRefresh();
            } else {
                this.stopAutoRefresh();
            }
        });
        
        // Manual refresh button
        document.getElementById('manualRefresh').addEventListener('click', () => {
            this.refreshData();
        });
    }
    
    startAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
        
        if (!this.controls.autoRefresh) return;
        
        this.refreshTimer = 30;
        this.updateRefreshTimer();
        
        this.refreshInterval = setInterval(() => {
            this.refreshTimer--;
            this.updateRefreshTimer();
            
            if (this.refreshTimer <= 0) {
                this.refreshData();
                this.refreshTimer = 30;
            }
        }, 1000);
    }
    
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }
    
    updateRefreshTimer() {
        const timerElement = document.getElementById('nextRefreshTime');
        if (timerElement) {
            timerElement.textContent = `${this.refreshTimer}վ`;
        }
    }
    
    async refreshData() {
        console.log('🔄 Refreshing threat data...');
        try {
            await this.loadThreatData();
            console.log('✅ Data refreshed successfully');
        } catch (error) {
            console.error('❌ Failed to refresh data:', error);
        }
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = show ? 'flex' : 'none';
        }
    }
    
    showError(message) {
        console.error(message);
        // Could implement toast notifications here
        alert(`❌ ${message}`);
    }
    
    destroy() {
        this.stopAutoRefresh();
        this.clearAttacks();
        if (this.map) {
            this.map.remove();
        }
    }
}

// Global instance for debugging
window.LiveThreatMap = LiveThreatMap;
