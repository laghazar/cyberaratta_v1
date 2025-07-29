from django.core.management.base import BaseCommand
from apps.url_email_analyzer.models_integrations import SecurityIntegration
import json


class Command(BaseCommand):
    help = 'Load initial security integrations'

    def handle(self, *args, **options):
        # VirusTotal Integration
        virustotal, created = SecurityIntegration.objects.get_or_create(
            slug='virustotal',
            defaults={
                'display_name': 'VirusTotal',
                'description': 'Համաշխարհային վիրուսային բազա',
                'integration_type': 'url_scanner',
                'api_url': 'https://www.virustotal.com/vtapi/v2/url/report',
                'api_key': 'YOUR_VIRUSTOTAL_API_KEY',  # Admin should replace this
                'api_headers': json.dumps({
                    'Content-Type': 'application/json'
                }),
                'icon_class': 'fas fa-virus-slash',
                'color_class': 'text-primary',
                'status': 'active',
                'timeout_seconds': 30,
                'rate_limit_per_minute': 4,
                'priority': 1,
                'order': 1
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created VirusTotal integration'))
        else:
            self.stdout.write(self.style.WARNING('VirusTotal integration already exists'))

        # Kaspersky Integration
        kaspersky, created = SecurityIntegration.objects.get_or_create(
            slug='kaspersky',
            defaults={
                'display_name': 'Kaspersky OpenTIP',
                'description': 'Kaspersky անվտանգության բազա',
                'integration_type': 'url_scanner',
                'api_url': 'https://opentip.kaspersky.com/api/v1/search/url',
                'api_key': 'YOUR_KASPERSKY_API_KEY',  # Admin should replace this
                'api_headers': json.dumps({
                    'Content-Type': 'application/json'
                }),
                'icon_class': 'fas fa-shield-virus',
                'color_class': 'text-success',
                'status': 'active',
                'timeout_seconds': 30,
                'rate_limit_per_minute': 10,
                'priority': 2,
                'order': 2
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created Kaspersky integration'))
        else:
            self.stdout.write(self.style.WARNING('Kaspersky integration already exists'))

        # Google Safe Browsing (Coming Soon)
        safebrowsing, created = SecurityIntegration.objects.get_or_create(
            slug='safebrowsing',
            defaults={
                'display_name': 'Google Safe Browsing',
                'description': 'Google-ի անվտանգ դիտարկման API',
                'integration_type': 'url_scanner',
                'api_url': 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
                'api_key': '',  # Empty for now
                'api_headers': json.dumps({}),
                'icon_class': 'fab fa-google',
                'color_class': 'text-warning',
                'status': 'coming_soon',
                'timeout_seconds': 30,
                'rate_limit_per_minute': 1000,
                'priority': 3,
                'order': 3
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created Google Safe Browsing integration'))
        else:
            self.stdout.write(self.style.WARNING('Google Safe Browsing integration already exists'))

        # URLVoid (Coming Soon)
        urlvoid, created = SecurityIntegration.objects.get_or_create(
            slug='urlvoid',
            defaults={
                'display_name': 'URLVoid',
                'description': 'URLVoid անվտանգության ստուգում',
                'integration_type': 'url_scanner',
                'api_url': 'https://api.urlvoid.com/v1/{api_key}/host/{url}',
                'api_key': '',  # Empty for now
                'api_headers': json.dumps({}),
                'icon_class': 'fas fa-globe-americas',
                'color_class': 'text-info',
                'status': 'coming_soon',
                'timeout_seconds': 30,
                'rate_limit_per_minute': 200,
                'priority': 4,
                'order': 4
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created URLVoid integration'))
        else:
            self.stdout.write(self.style.WARNING('URLVoid integration already exists'))

        # PhishTank (Coming Soon)
        phishtank, created = SecurityIntegration.objects.get_or_create(
            slug='phishtank',
            defaults={
                'display_name': 'PhishTank',
                'description': 'PhishTank ֆիշինգ բազա',
                'integration_type': 'url_scanner',
                'api_url': 'https://checkurl.phishtank.com/checkurl/',
                'api_key': '',  # No API key needed
                'api_headers': json.dumps({}),
                'icon_class': 'fas fa-fish',
                'color_class': 'text-secondary',
                'status': 'coming_soon',
                'timeout_seconds': 30,
                'rate_limit_per_minute': 100,
                'priority': 5,
                'order': 5
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Created PhishTank integration'))
        else:
            self.stdout.write(self.style.WARNING('PhishTank integration already exists'))

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully loaded {SecurityIntegration.objects.count()} security integrations'
            )
        )
