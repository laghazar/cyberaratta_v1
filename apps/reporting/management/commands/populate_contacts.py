from django.core.management.base import BaseCommand
from apps.reporting.models import ContactInfo, ContactGuideline

class Command(BaseCommand):
    help = 'Create sample contact information for reporting'

    def handle(self, *args, **options):
        contacts_data = [
            {
                'contact_info': {
                    'name': 'ՀՀ Ոստիկանություն կիբեռանվտանգության բաժին',
                    'description': 'Կիբեռհանցագործությունների դեմ պայքարի հատուկ ծառայություն',
                    'phone': '102',
                    'email': 'cyber@police.am',
                    'website': 'https://www.police.am',
                    'is_emergency': True,
                    'order': 1
                },
                'guideline': {
                    'when_to_contact': 'Կիբεռհանցագործության դեպքում, ֆինանսական կորուստների դեպքում, անմիջական սպառնալիքների դեպքում',
                    'required_documents': 'Նույնականացման փաստաթուղթ, զեկուցվող դեպքի մանրամասներ, էկրանի պատկերներ (եթե կան)',  
                    'process_description': '1. Զանգահարել 102\n2. Մանրամասներ տրամադրել\n3. Ստանալ գործի համար\n4. Հետագա հետևել',
                    'response_time': '24 ժամ',
                    'additional_info': 'Արտակարգ դեպքերում 24/7 մատչելի'
                }
            },
            {
                'contact_info': {
                    'name': 'Հայկական համակարգչային արտակարգ իրավիճակների գործակալություն (CERT-AM)',
                    'description': 'Կիբեռանվտանգության ազգային կենտրոն',
                    'phone': '+374 10 544 555',
                    'email': 'info@cert.am',
                    'website': 'https://www.cert.am',
                    'is_emergency': False,
                    'order': 2
                },
                'guideline': {
                    'when_to_contact': 'Կիբեռհարձակումների, վիրուսների, տեխնիկական անվտանգության խնդիրների դեպքում',
                    'required_documents': 'Տեխնիկական նկարագրություն, log ֆայլեր, հարձակման մանրամասներ',
                    'process_description': '1. Էլ. փոստով դիմել\n2. Տեխնիկական տվյալներ ներկայացնել\n3. CERT թիմի գնահատում\n4. Խորհրդատվություն և լուծումներ',
                    'response_time': '2-3 աշխատանքային օր',
                    'additional_info': 'Տեխնիկական կիբեռանվտանգության հարցերի համար գիտելով ֆորում'
                }
            },
            {
                'contact_info': {
                    'name': 'ՀՀ Տեղեկատվական տեխնոլոգիաների զարգացման կենտրոն',
                    'description': 'Պետական կառավարման ոլորտում ՏՏ անվտանգության գերակա գործակալություն',
                    'phone': '+374 10 569 900',
                    'email': 'info@itdc.am',
                    'website': 'https://www.itdc.am',
                    'is_emergency': False,
                    'order': 3
                },
                'guideline': {
                    'when_to_contact': 'Պետական ծառայությունների հետ կապված կիբեռսպառնալիքների դեպքում',
                    'required_documents': 'Դիմում, փաստաթղթային ապացույցներ, կապի տվյալներ',
                    'process_description': '1. Գրավոր դիմում\n2. Փաստաթղթերի քննում\n3. Փորձագիտական գնահատում\n4. Պաշտոնական պատասխան',
                    'response_time': '5-7 աշխատանքային օր',
                    'additional_info': 'Պետական կառույցների հետ կապված հարցերի համար'
                }
            },
            {
                'contact_info': {
                    'name': 'Բանկային կիբեռանվտանգության օգնական գիծ',
                    'description': 'Բանկային գործառնությունների անվտանգության վերաբերյալ',
                    'phone': '8-800-00-00',
                    'email': 'security@banking.am',
                    'website': 'https://www.cba.am',
                    'is_emergency': False,
                    'order': 4
                },
                'guideline': {
                    'when_to_contact': 'Բանկային կարտերի, հաշիվների, փոխանցման կասկածելի գործարքների դեպքում',
                    'required_documents': 'Բանկային կարտի տվյալներ, գործարքի մանրամասներ, էլ. նամակների պատճեններ',
                    'process_description': '1. Անմիջապես զանգահարել\n2. Կարտը կասեցնել\n3. Խարդախության մանրամասներ տրամադրել\n4. Հետաքննական գործընթաց',
                    'response_time': 'Անմիջապես',
                    'additional_info': 'Բանկային կարտերի անվտանգության հարցերի համար 24/7'
                }
            },
            {
                'contact_info': {
                    'name': '24/7 Կիբեռանվտանգության հատակ գիծ',
                    'description': 'Արտակարգ իրավիճակների համար 24 ժամ մատչելի գիծ',
                    'phone': '911',
                    'email': 'emergency@cybersecurity.am',
                    'is_emergency': True,
                    'order': 0
                },
                'guideline': {
                    'when_to_contact': 'Արտակարգ կիբեռսպառնալիքների, անմիջական ֆինանսական վնասի, անձնական տվյալների արտահոսքի դեպքում',
                    'required_documents': 'Նվազագույն տեղեկություններ, մանրամասները կարելի է տրամադրել հետագայում',
                    'process_description': '1. Անմիջապես զանգահարել 911\n2. "Կիբեռսպառնալիք" նշել\n3. Հիմնական մանրամասներ\n4. Արագ արձագանքում',
                    'response_time': 'Անմիջապես',
                    'additional_info': 'Արտակարգ իրավիճակների համար միայն, 24/7 մատչելի'
                }
            }
        ]

        created_count = 0
        updated_count = 0

        for contact_data in contacts_data:
            contact, created = ContactInfo.objects.get_or_create(
                name=contact_data['contact_info']['name'],
                defaults=contact_data['contact_info']
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Ստեղծվել է: {contact.name}')
                )
            else:
                # Update existing contact
                for key, value in contact_data['contact_info'].items():
                    setattr(contact, key, value)
                contact.save()
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'Թարմացվել է: {contact.name}')
                )
            
            # Create or update guideline
            if 'guideline' in contact_data:
                guideline, guideline_created = ContactGuideline.objects.get_or_create(
                    contact=contact,
                    defaults=contact_data['guideline']
                )
                
                if not guideline_created:
                    # Update existing guideline
                    for key, value in contact_data['guideline'].items():
                        setattr(guideline, key, value)
                    guideline.save()
                    self.stdout.write(
                        self.style.WARNING(f'Ուղեցույցը թարմացվել է: {contact.name}')
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(f'Ուղեցույցը ստեղծվել է: {contact.name}')
                    )

        self.stdout.write(
            self.style.SUCCESS(
                f'Գործողությունը ավարտվել է: {created_count} ստեղծված, {updated_count} թարմացված'
            )
        )
