/**
 * URL Checker and Email Phishing Checker utility functions for the frontend
 * Unified handling for both URL checking and Email phishing analysis
 */

// Global variable to track current input type
let currentInputType = 'url';

/**
 * Initialize the page when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', function() {
    // The initialization is now handled in the template itself
    // This file provides utility functions that are called from the template
});

/**
 * Update the recent URL checks list
 * @param {string} url - The URL that was checked
 * @param {string} status - The status of the check (safe, malicious, suspicious, pending)
 * @param {string} statusDisplay - The human-readable status text
 */
function updateRecentChecks(url, status, statusDisplay) {
    // Get the container for recent URLs
    const recentUrlsContainer = document.getElementById('recentUrls');
    
    if (!recentUrlsContainer) return;
    
    // Clear the initial message if it exists
    if (recentUrlsContainer.querySelector('p:not(.checked-url)')) {
        recentUrlsContainer.innerHTML = '';
    }
    
    // Determine status icon and color
    let statusIcon, statusColor;
    switch(status) {
        case 'safe':
            statusIcon = 'fa-shield-alt';
            statusColor = 'text-success';
            break;
        case 'malicious':
            statusIcon = 'fa-exclamation-triangle';
            statusColor = 'text-danger';
            break;
        case 'suspicious':
            statusIcon = 'fa-exclamation-circle';
            statusColor = 'text-warning';
            break;
        default:
            statusIcon = 'fa-search';
            statusColor = 'text-primary';
    }
    
    // Create a new URL entry element
    const urlElement = document.createElement('p');
    urlElement.className = 'checked-url mb-2 d-flex align-items-center';
    urlElement.setAttribute('data-url', url);
    
    // Format URL for display (truncate if too long)
    const displayUrl = url.length > 50 ? url.substring(0, 47) + '...' : url;
    
    // Set HTML content with appropriate status styling
    urlElement.innerHTML = `
        <i class="fas ${statusIcon} me-2 ${statusColor}"></i>
        <a href="#" class="text-reset text-decoration-none flex-grow-1" 
           title="${url}" onclick="fillUrlInput('${url}'); return false;">
            ${displayUrl}
        </a>
        <span class="badge bg-light text-dark ms-2">${statusDisplay}</span>
    `;
    
    // Add to the container (at the beginning)
    recentUrlsContainer.insertBefore(urlElement, recentUrlsContainer.firstChild);
    
    // Limit to 5 recent URLs
    const allUrls = recentUrlsContainer.querySelectorAll('.checked-url');
    if (allUrls.length > 5) {
        recentUrlsContainer.removeChild(allUrls[allUrls.length - 1]);
    }
}

/**
 * Fill the URL input field with a previously checked URL
 * @param {string} url - The URL to fill in the input
 */
function fillUrlInput(url) {
    const urlInput = document.getElementById('url_input_main');
    const urlTypeRadio = document.getElementById('url_type');
    
    if (urlInput && urlTypeRadio) {
        // Switch to URL type if not already selected
        if (!urlTypeRadio.checked) {
            urlTypeRadio.click();
        }
        
        // Fill the URL
        urlInput.value = url;
        urlInput.focus();
        
        // Scroll to the form
        const form = document.getElementById('unifiedCheckForm');
        if (form) {
            form.scrollIntoView({ behavior: 'smooth' });
        }
    }
}

/**
 * Get CSRF token from cookies
 * @returns {string} The CSRF token value
 */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Show loading spinner in a specific element
 * @param {string} elementId - The ID of the element to show loading in
 */
function showLoadingInElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="text-center p-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <p class="mt-2">Վերլուծվում է...</p>
            </div>
        `;
    }
}

/**
 * Show error message in a specific element
 * @param {string} elementId - The ID of the element to show error in
 * @param {string} message - The error message to display
 */
function showErrorInElement(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Սխալ:</strong> ${message}
            </div>
        `;
    }
}

/**
 * Show success message in a specific element
 * @param {string} elementId - The ID of the element to show success in
 * @param {string} message - The success message to display
 */
function showSuccessInElement(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.innerHTML = `
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>
                <strong>Հաջողություն:</strong> ${message}
            </div>
        `;
    }
}

/**
 * Format file size for display
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size string
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Validate URL format
 * @param {string} url - URL to validate
 * @returns {boolean} True if URL is valid
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Sanitize HTML content to prevent XSS
 * @param {string} str - String to sanitize
 * @returns {string} Sanitized string
 */
function sanitizeHtml(str) {
    const temp = document.createElement('div');
    temp.textContent = str;
    return temp.innerHTML;
}

/**
 * Show notification toast
 * @param {string} message - Message to show
 * @param {string} type - Type of notification (success, error, warning, info)
 */
function showNotification(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} position-fixed`;
    toast.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        max-width: 300px;
        opacity: 0;
        transition: opacity 0.3s ease;
    `;
    
    // Set content based on type
    let icon;
    switch(type) {
        case 'success':
            icon = 'fa-check-circle';
            break;
        case 'error':
        case 'danger':
            icon = 'fa-exclamation-triangle';
            break;
        case 'warning':
            icon = 'fa-exclamation-circle';
            break;
        default:
            icon = 'fa-info-circle';
    }
    
    toast.innerHTML = `
        <i class="fas ${icon} me-2"></i>
        ${sanitizeHtml(message)}
        <button type="button" class="btn-close float-end" onclick="this.parentElement.remove()"></button>
    `;
    
    // Add to document
    document.body.appendChild(toast);
    
    // Show with animation
    setTimeout(() => {
        toast.style.opacity = '1';
    }, 100);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
        }, 300);
    }, 5000);
}

/**
 * Copy text to clipboard
 * @param {string} text - Text to copy
 * @param {string} successMessage - Message to show on success
 */
function copyToClipboard(text, successMessage = 'Կոպի արվեց!') {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function() {
            showNotification(successMessage, 'success');
        }).catch(function() {
            fallbackCopyTextToClipboard(text, successMessage);
        });
    } else {
        fallbackCopyTextToClipboard(text, successMessage);
    }
}

/**
 * Fallback copy method for older browsers
 * @param {string} text - Text to copy
 * @param {string} successMessage - Message to show on success
 */
function fallbackCopyTextToClipboard(text, successMessage) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification(successMessage, 'success');
    } catch (err) {
        showNotification('Կոպի չհաջողվեց', 'error');
    }
    
    document.body.removeChild(textArea);
}

/**
 * Update the recent URL checks list
 * @param {string} url - The URL that was checked
 * @param {string} status - The status of the check (safe, malicious, suspicious, pending)
 * @param {string} statusDisplay - The human-readable status text
 */
function updateRecentChecks(url, status, statusDisplay) {
    // Get the container for recent URLs
    const recentUrlsContainer = document.getElementById('recentUrls');
    
    // Clear the initial message if it exists
    if (recentUrlsContainer.querySelector('p:not(.checked-url)')) {
        recentUrlsContainer.innerHTML = '';
    }
    
    // Determine status icon and color
    let statusIcon, statusColor;
    switch(status) {
        case 'safe':
            statusIcon = 'fa-shield-alt';
            statusColor = 'text-success';
            break;
        case 'malicious':
            statusIcon = 'fa-exclamation-triangle';
            statusColor = 'text-danger';
            break;
        case 'suspicious':
            statusIcon = 'fa-exclamation-circle';
            statusColor = 'text-warning';
            break;
        default:
            statusIcon = 'fa-search';
            statusColor = 'text-primary';
    }
    
    // Create a new URL entry element
    const urlElement = document.createElement('p');
    urlElement.className = 'checked-url mb-2 d-flex align-items-center';
    urlElement.setAttribute('data-url', url);
    
    // Format URL for display (truncate if too long)
    const displayUrl = url.length > 30 ? url.substring(0, 27) + '...' : url;
    
    // Set HTML content with appropriate status styling
    urlElement.innerHTML = `
        <i class="fas ${statusIcon} me-2 ${statusColor}"></i>
        <a href="#" class="text-reset text-decoration-none flex-grow-1" 
           title="${url}" onclick="fillUrlInput('${url}'); return false;">
            ${displayUrl}
        </a>
        <span class="badge bg-light text-dark ms-2">${statusDisplay}</span>
    `;
    
    // Add to the container (at the beginning)
    recentUrlsContainer.insertBefore(urlElement, recentUrlsContainer.firstChild);
    
    // Limit to 5 recent URLs
    const allUrls = recentUrlsContainer.querySelectorAll('.checked-url');
    if (allUrls.length > 5) {
        recentUrlsContainer.removeChild(allUrls[allUrls.length - 1]);
    }
}

/**
 * Fill the URL input field with a previously checked URL
 * @param {string} url - The URL to fill in the input
 */
function fillUrlInput(url) {
    const urlInput = document.getElementById('url_input');
    urlInput.value = url;
    urlInput.focus();
    // Scroll to the form
    document.getElementById('urlCheckForm').scrollIntoView({ behavior: 'smooth' });
}

/**
 * Get CSRF token from cookies
 * @returns {string} The CSRF token value
 */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
