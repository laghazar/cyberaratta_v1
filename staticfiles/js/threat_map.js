// Threat Map JavaScript Functions

class ThreatMap {
    constructor() {
        this.refreshInterval = 30000; // 30 seconds
        this.charts = {};
        this.init();
    }

    init() {
        this.loadThreatData();
        this.initCharts();
        this.startAutoRefresh();
        this.bindEvents();
    }

    async loadThreatData() {
        try {
            this.showLoading(true);
            
            // Load statistics
            const statsResponse = await fetch('/threat-map/api/stats/');
            const stats = await statsResponse.json();
            this.updateStats(stats);

            // Load threats
            const threatsResponse = await fetch('/threat-map/api/threats/');
            const threats = await threatsResponse.json();
            this.updateThreats(threats);

            // Load phishing URLs
            const urlsResponse = await fetch('/threat-map/api/phishing-urls/');
            const urls = await urlsResponse.json();
            this.updatePhishingUrls(urls);

            this.showLoading(false);
        } catch (error) {
            console.error('Error loading threat data:', error);
            this.showError('Տվյալների բեռնման սխալ');
            this.showLoading(false);
        }
    }

    updateStats(stats) {
        const statElements = {
            'total-threats': stats.total_threats || 0,
            'active-threats': stats.active_threats || 0,
            'resolved-threats': stats.resolved_threats || 0,
            'phishing-urls': stats.phishing_urls || 0
        };

        Object.entries(statElements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                this.animateNumber(element, parseInt(value));
            }
        });
    }

    updateThreats(threats) {
        const container = document.getElementById('threats-list');
        if (!container) return;

        container.innerHTML = '';
        
        if (threats.length === 0) {
            container.innerHTML = '<div class="text-center text-muted">Այս պահին վտանգներ չեն հայտնաբերվել</div>';
            return;
        }

        threats.forEach(threat => {
            const threatElement = this.createThreatElement(threat);
            container.appendChild(threatElement);
        });
    }

    updatePhishingUrls(urls) {
        const container = document.getElementById('phishing-urls-list');
        if (!container) return;

        container.innerHTML = '';
        
        if (urls.length === 0) {
            container.innerHTML = '<div class="text-center text-muted">Ֆիշինգ հղումներ չեն հայտնաբերվել</div>';
            return;
        }

        urls.forEach(url => {
            const urlElement = this.createPhishingUrlElement(url);
            container.appendChild(urlElement);
        });
    }

    createThreatElement(threat) {
        const div = document.createElement('div');
        div.className = 'threat-item';
        
        const severityClass = this.getSeverityClass(threat.severity);
        const timeAgo = this.getTimeAgo(threat.created_at);
        
        div.innerHTML = `
            <div class="threat-meta">
                <span class="threat-badge badge-severity-${threat.severity}">${this.getSeverityLabel(threat.severity)}</span>
                <span class="threat-badge badge-category-${threat.category}">${this.getCategoryLabel(threat.category)}</span>
                <span class="threat-time">${timeAgo}</span>
            </div>
            <div class="threat-description">
                <strong>${threat.title}</strong>
                <p>${threat.description}</p>
            </div>
        `;
        
        return div;
    }

    createPhishingUrlElement(url) {
        const div = document.createElement('div');
        div.className = 'threat-item';
        
        const statusClass = this.getStatusClass(url.status);
        const timeAgo = this.getTimeAgo(url.last_checked);
        
        div.innerHTML = `
            <a href="${url.url}" class="threat-url" target="_blank" rel="noopener">${url.url}</a>
            <div class="threat-meta">
                <span class="threat-badge badge-status-${url.status}">${this.getStatusLabel(url.status)}</span>
                <span class="platform-badge">${url.platform_source}</span>
                <span class="threat-time">${timeAgo}</span>
            </div>
        `;
        
        return div;
    }

    initCharts() {
        this.initThreatSeverityChart();
        this.initThreatCategoryChart();
        this.initTimelineChart();
    }

    initThreatSeverityChart() {
        const ctx = document.getElementById('severity-chart');
        if (!ctx) return;

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Բարձր', 'Միջին', 'Ցածր'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#ff0055', '#ff9800', '#4caf50'],
                    borderColor: ['#ff0055', '#ff9800', '#4caf50'],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#ffffff' }
                    }
                }
            }
        });
    }

    initThreatCategoryChart() {
        const ctx = document.getElementById('category-chart');
        if (!ctx) return;

        this.charts.category = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Բանկային', 'Սոց. ցանցեր', 'SMS', 'Էլ. փոստ', 'Կրիպտո', 'Պետական'],
                datasets: [{
                    label: 'Գործադիր վտանգներ',
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(0, 204, 255, 0.2)',
                    borderColor: '#00ccff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    x: {
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                }
            }
        });
    }

    initTimelineChart() {
        const ctx = document.getElementById('timeline-chart');
        if (!ctx) return;

        this.charts.timeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Նոր վտանգներ',
                    data: [],
                    borderColor: '#ff0055',
                    backgroundColor: 'rgba(255, 0, 85, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        labels: { color: '#ffffff' }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    x: {
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                }
            }
        });
    }

    startAutoRefresh() {
        setInterval(() => {
            this.loadThreatData();
        }, this.refreshInterval);
    }

    bindEvents() {
        // Refresh button
        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadThreatData();
            });
        }

        // URL status check buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('check-url-btn')) {
                const url = e.target.dataset.url;
                this.checkUrlStatus(url);
            }
        });
    }

    async checkUrlStatus(url) {
        try {
            const response = await fetch('/threat-map/api/check-url/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ url: url })
            });
            
            const result = await response.json();
            this.showNotification(result.message, result.status === 'success' ? 'success' : 'error');
            
            // Refresh data after check
            setTimeout(() => this.loadThreatData(), 1000);
        } catch (error) {
            console.error('Error checking URL:', error);
            this.showError('URL-ի ստուգման սխալ');
        }
    }

    // Utility methods
    animateNumber(element, targetValue) {
        const currentValue = parseInt(element.textContent) || 0;
        const increment = Math.ceil((targetValue - currentValue) / 20);
        
        if (currentValue < targetValue) {
            element.textContent = currentValue + increment;
            setTimeout(() => this.animateNumber(element, targetValue), 50);
        } else {
            element.textContent = targetValue;
        }
    }

    getSeverityClass(severity) {
        const classes = {
            'high': 'danger',
            'medium': 'warning',
            'low': 'success'
        };
        return classes[severity] || 'secondary';
    }

    getSeverityLabel(severity) {
        const labels = {
            'high': 'Բարձր',
            'medium': 'Միջին',
            'low': 'Ցածր'
        };
        return labels[severity] || severity;
    }

    getCategoryLabel(category) {
        const labels = {
            'banking': 'Բանկային',
            'social_media': 'Սոց. ցանցեր',
            'sms': 'SMS',
            'email': 'Էլ. փոստ',
            'cryptocurrency': 'Կրիպտո',
            'government': 'Պետական',
            'other': 'Այլ'
        };
        return labels[category] || category;
    }

    getStatusClass(status) {
        const classes = {
            'active': 'danger',
            'inactive': 'success',
            'suspicious': 'warning',
            'malicious': 'danger',
            'safe': 'success'
        };
        return classes[status] || 'secondary';
    }

    getStatusLabel(status) {
        const labels = {
            'active': 'Գործուն',
            'inactive': 'Ոչ գործուն',
            'suspicious': 'Կասկածելի',
            'malicious': 'Վնասակար',
            'safe': 'Անվտանգ'
        };
        return labels[status] || status;
    }

    getTimeAgo(timestamp) {
        const now = new Date();
        const time = new Date(timestamp);
        const diffInSeconds = Math.floor((now - time) / 1000);
        
        if (diffInSeconds < 60) return 'Հիմա';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} րոպե առաջ`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} ժամ առաջ`;
        return `${Math.floor(diffInSeconds / 86400)} օր առաջ`;
    }

    getCSRFToken() {
        return document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
    }

    showLoading(show) {
        const loadingElements = document.querySelectorAll('.loading-spinner');
        loadingElements.forEach(el => {
            el.style.display = show ? 'inline-block' : 'none';
        });
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} notification`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }

    showError(message) {
        this.showNotification(message, 'danger');
    }
}

// Initialize threat map when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.threatMap = new ThreatMap();
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    .notification {
        animation: slideIn 0.3s ease;
    }
`;
document.head.appendChild(style);