"""
Backend service to support dynamic integrations while keeping existing UI
This allows admins to add new integrations through admin panel
"""

from .models_integrations import SecurityIntegration
from .dynamic_integrations import integration_service


def get_backend_integration_mapping():
    """
    Get mapping of integration slugs to their backend functions
    This allows existing UI to work with dynamic integrations
    """
    active_integrations = integration_service.get_active_integrations()
    
    mapping = {}
    for integration in active_integrations:
        if integration.slug == 'virustotal':
            from .utils import check_url_virustotal
            mapping['virustotal'] = check_url_virustotal
        elif integration.slug == 'kaspersky':
            from .utils import check_url_kaspersky
            mapping['kaspersky'] = check_url_kaspersky
        # Future integrations will be added here automatically
    
    return mapping


def check_with_dynamic_integration(integration_slug, url):
    """
    Check URL with a dynamic integration
    Falls back to old methods for backwards compatibility
    """
    try:
        integration = SecurityIntegration.objects.get(
            slug=integration_slug, 
            status='active'
        )
        
        # Use new dynamic service
        result = integration_service.check_url_with_integration(integration, url)
        
        # Convert to old format for compatibility
        if result.get('status') == 'malicious':
            return {'status': 'malicious', 'confidence': result.get('confidence', 'medium')}
        elif result.get('status') == 'suspicious':
            return {'status': 'suspicious', 'confidence': result.get('confidence', 'medium')}
        elif result.get('status') == 'safe':
            return {'status': 'safe', 'confidence': result.get('confidence', 'high')}
        else:
            return {'status': 'pending', 'confidence': 'low'}
            
    except SecurityIntegration.DoesNotExist:
        # Fallback to old methods
        if integration_slug == 'virustotal':
            from .utils import check_url_virustotal
            return check_url_virustotal(url)
        elif integration_slug == 'kaspersky':
            from .utils import check_url_kaspersky
            return check_url_kaspersky(url)
    
    return {'status': 'pending', 'confidence': 'low'}


def get_available_sources():
    """
    Get list of available sources for UI
    Combines old hardcoded sources with dynamic ones
    """
    sources = []
    
    # Add dynamic integrations
    active_integrations = integration_service.get_active_integrations()
    for integration in active_integrations:
        sources.append({
            'slug': integration.slug,
            'name': integration.display_name,
            'description': integration.description,
            'icon': integration.icon_class or 'fas fa-shield',
            'status': integration.status
        })
    
    # Ensure backwards compatibility with hardcoded sources
    existing_slugs = [s['slug'] for s in sources]
    if 'virustotal' not in existing_slugs:
        sources.append({
            'slug': 'virustotal',
            'name': 'VirusTotal',
            'description': 'Համաշխարհային վիրուսային բազա',
            'icon': 'fas fa-virus-slash',
            'status': 'active'
        })
    
    if 'kaspersky' not in existing_slugs:
        sources.append({
            'slug': 'kaspersky', 
            'name': 'Kaspersky',
            'description': 'Kaspersky անվտանգության բազա',
            'icon': 'fas fa-shield-virus',
            'status': 'active'
        })
    
    return sources
