/**
 * URL Checker utility functions for the frontend
 * Helper functions for managing URL check results and recent checks
 */

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
