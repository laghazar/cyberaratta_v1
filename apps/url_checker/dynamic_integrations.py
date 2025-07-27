import requests
import time
import logging
from typing import Dict, List, Any, Optional
from django.core.cache import cache
from django.conf import settings
from .models_integrations import SecurityIntegration, IntegrationResult

logger = logging.getLogger(__name__)


class DynamicIntegrationService:
    """Service for managing dynamic security integrations"""
    
    def __init__(self):
        self.cache_timeout = 300  # 5 minutes
    
    def get_active_integrations(self, integration_type: str = 'url_scanner') -> List[SecurityIntegration]:
        """Get all active integrations for specific type"""
        cache_key = f"active_integrations_{integration_type}"
        integrations = cache.get(cache_key)
        
        if integrations is None:
            integrations = list(SecurityIntegration.objects.filter(
                status='active',
                integration_type=integration_type
            ).order_by('order', 'priority'))
            cache.set(cache_key, integrations, self.cache_timeout)
        
        return integrations
    
    def get_all_integrations_for_dropdown(self, integration_type: str = 'url_scanner') -> List[Dict]:
        """Get all integrations formatted for dropdown display"""
        cache_key = f"dropdown_integrations_{integration_type}"
        dropdown_data = cache.get(cache_key)
        
        if dropdown_data is None:
            integrations = SecurityIntegration.objects.filter(
                integration_type=integration_type
            ).order_by('order', 'priority')
            
            dropdown_data = []
            for integration in integrations:
                dropdown_data.append({
                    'slug': integration.slug,
                    'display_name': integration.display_name,
                    'description': integration.description,
                    'icon_class': integration.icon_class,
                    'color_class': integration.color_class,
                    'status': integration.status,
                    'is_active': integration.is_active,
                    'has_api_config': integration.has_api_config,
                })
            
            cache.set(cache_key, dropdown_data, self.cache_timeout)
        
        return dropdown_data
    
    def check_url_with_integration(self, integration: SecurityIntegration, url: str) -> Dict[str, Any]:
        """Check URL with specific integration"""
        if not integration.has_api_config:
            return {
                'status': 'error',
                'message': f"{integration.display_name} API configuration incomplete",
                'confidence': 'low'
            }
        
        try:
            start_time = time.time()
            
            # Prepare headers
            headers = {
                'User-Agent': 'CyberAratta-Security-Platform/1.0',
                'Content-Type': 'application/json',
                **integration.api_headers
            }
            
            # Add API key to headers or params based on integration
            if 'apikey' in integration.api_url.lower() or 'api_key' in integration.api_url.lower():
                # API key in URL
                api_url = integration.api_url.format(url=url, api_key=integration.api_key)
            else:
                # API key in headers
                headers['X-API-Key'] = integration.api_key
                api_url = integration.api_url.format(url=url)
            
            # Make request
            response = requests.get(
                api_url,
                headers=headers,
                timeout=integration.timeout_seconds
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                result_data = response.json()
                processed_result = self._process_integration_response(integration, result_data)
                processed_result['response_time_ms'] = response_time
                processed_result['raw_response'] = result_data
                
                return processed_result
            else:
                return {
                    'status': 'error',
                    'message': f"HTTP {response.status_code}: {response.text[:200]}",
                    'confidence': 'low',
                    'response_time_ms': response_time
                }
                
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'message': f"Timeout after {integration.timeout_seconds} seconds",
                'confidence': 'low'
            }
        except Exception as e:
            logger.error(f"Integration {integration.slug} error: {str(e)}")
            return {
                'status': 'error',
                'message': f"Integration error: {str(e)}",
                'confidence': 'low'
            }
    
    def _process_integration_response(self, integration: SecurityIntegration, raw_data: Dict) -> Dict[str, Any]:
        """Process raw API response based on integration type"""
        
        # Generic processing - can be extended for specific integrations
        if integration.slug == 'virustotal':
            return self._process_virustotal_response(raw_data)
        elif integration.slug == 'kaspersky':
            return self._process_kaspersky_response(raw_data)
        else:
            return self._process_generic_response(raw_data)
    
    def _process_virustotal_response(self, data: Dict) -> Dict[str, Any]:
        """Process VirusTotal API response"""
        try:
            stats = data.get('data', {}).get('attributes', {}).get('stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            clean = stats.get('harmless', 0)
            
            total_engines = malicious + suspicious + undetected + clean
            
            if malicious > 0:
                status = 'malicious'
                confidence = 'high' if malicious > 5 else 'medium'
            elif suspicious > 0:
                status = 'suspicious'
                confidence = 'medium'
            else:
                status = 'safe'
                confidence = 'high' if total_engines > 50 else 'medium'
            
            return {
                'status': status,
                'confidence': confidence,
                'details': {
                    'malicious_engines': malicious,
                    'suspicious_engines': suspicious,
                    'clean_engines': clean,
                    'total_engines': total_engines,
                    'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date')
                }
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Failed to process VirusTotal response: {str(e)}",
                'confidence': 'low'
            }
    
    def _process_kaspersky_response(self, data: Dict) -> Dict[str, Any]:
        """Process Kaspersky API response"""
        try:
            zone = data.get('Zone', 'Unknown')
            categories = data.get('CategoriesWithConfidence', [])
            
            if zone in ['Red', 'Malicious']:
                status = 'malicious'
                confidence = 'high'
            elif zone in ['Yellow', 'Suspicious']:
                status = 'suspicious' 
                confidence = 'medium'
            elif zone in ['Green', 'Clean']:
                status = 'safe'
                confidence = 'high'
            else:
                status = 'pending'
                confidence = 'low'
            
            return {
                'status': status,
                'confidence': confidence,
                'details': {
                    'zone': zone,
                    'categories': categories,
                    'verdict': data.get('verdict', 'Unknown')
                }
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': f"Failed to process Kaspersky response: {str(e)}",
                'confidence': 'low'
            }
    
    def _process_generic_response(self, data: Dict) -> Dict[str, Any]:
        """Process generic API response"""
        # Try to extract common fields
        status = 'pending'
        confidence = 'medium'
        
        # Look for common status indicators
        if 'malicious' in str(data).lower() or 'threat' in str(data).lower():
            status = 'malicious'
            confidence = 'medium'
        elif 'clean' in str(data).lower() or 'safe' in str(data).lower():
            status = 'safe'
            confidence = 'medium'
        elif 'suspicious' in str(data).lower():
            status = 'suspicious'
            confidence = 'medium'
        
        return {
            'status': status,
            'confidence': confidence,
            'details': data
        }
    
    def check_url_with_all_active(self, url: str, url_check_instance) -> Dict[str, Any]:
        """Check URL with all active integrations"""
        active_integrations = self.get_active_integrations()
        results = {}
        integration_results = []
        
        for integration in active_integrations:
            result = self.check_url_with_integration(integration, url)
            results[integration.slug] = result
            
            # Save to database
            IntegrationResult.objects.update_or_create(
                integration=integration,
                url_check=url_check_instance,
                defaults={
                    'status': result.get('status', 'pending'),
                    'confidence': result.get('confidence', 'medium'),
                    'raw_response': result.get('raw_response', {}),
                    'processed_data': result.get('details', {}),
                    'response_time_ms': result.get('response_time_ms')
                }
            )
            
            integration_results.append({
                'name': integration.display_name,
                'slug': integration.slug,
                'status': result.get('status'),
                'confidence': result.get('confidence'),
                'response_time': result.get('response_time_ms')
            })
        
        return {
            'integration_results': integration_results,
            'raw_results': results
        }
    
    def clear_cache(self):
        """Clear integration cache"""
        cache_keys = [
            'active_integrations_url_scanner',
            'dropdown_integrations_url_scanner'
        ]
        for key in cache_keys:
            cache.delete(key)


# Initialize service instance
integration_service = DynamicIntegrationService()
