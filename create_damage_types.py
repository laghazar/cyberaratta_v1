#!/usr/bin/env python
"""
Create DamageType data for CyberAratta reporting system
Run this with: python create_damage_types.py
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberaratta.settings')
django.setup()

from apps.reporting.models import DamageType

def create_damage_types():
    """Create damage types based on the original choices"""
    print("Creating damage types...")
    
    damage_types_data = [
        # Data breach category
        ('data_breach', 'Անձնական տվյալների արտահոսք', 'Անուն, ազգանուն, անձնագիր, հասցե, հեռախոս, էլ. փոստ', 1),
        ('data_breach', 'Մուտքի տվյալների գողություն', 'Գաղտնաբառեր, 2FA կոդեր, էլ. նամակներ', 2),
        ('data_breach', 'Բանկային տվյալների արտահոսք', 'Քարտի համարը, CVV, հաշվի մուտքեր', 3),
        ('data_breach', 'Առաջադեմ անձնական տվյալների արտահոսք', 'Բժշկական տվյալներ, կրթության, աշխատավայրի տվյալներ', 4),
        ('data_breach', 'Պետական/պաշտոնական տվյալների արտահոսք', 'Գաղտնի պետական կամ պաշտոնական տեղեկություններ', 5),
        ('data_breach', 'Տվյալների կորուստ/ոչնչացում', 'Հատկապես պահոցներում', 6),
        ('data_breach', 'Անհատական գաղտնիության խախտում', 'Սոց. ցանցերում անձնական լուսանկարներ կամ գրառումներ', 7),
        
        # Financial loss category
        ('financial_loss', 'Չարտոնված գումարի հանում', 'Բանկային հաշվից կամ վարկային քարտից', 1),
        ('financial_loss', 'Չարտոնված վճարումներ/փոխանցումներ', 'Անգամ փոքր գումարներ', 2),
        ('financial_loss', 'Վճարովի ծառայությունների չարաշահում', 'Բոտերի, ֆիշինգի միջոցով', 3),
        ('financial_loss', 'Ֆինանսական տվյալների կեղծում', 'Ֆինանսական տվյալների չարաշահում', 4),
        ('financial_loss', 'Վարկերի չարաշահում իմ անունով', 'Վարկերի կամ ֆինանսական պարտավորությունների չարաշահում', 5),
        ('financial_loss', 'Անհայտ վճարումներ/գումարների անհետացում', 'Անհայտ հավելյալ վճարումներ', 6),
        
        # Account loss category
        ('account_loss', 'Օգտահաշվի մուտքի կորուստ', 'Չկարողացա վերականգնել մուտքը', 1),
        ('account_loss', 'Անձնական հաղորդագրությունների գաղտնիության խախտում', 'Խախտվել է հաշվի անձնական հաղորդագրությունների գաղտնիությունը', 2),
        ('account_loss', 'Օգտահաշվի չարամիտ օգտագործում', 'Խաբեությամբ մուտք, հրապարակումներ', 3),
        ('account_loss', 'Օգտահաշվի միջոցով խարդախություն', 'Օգտահաշվի միջոցով խարդախություն կամ վիրուսային տարածում', 4),
        ('account_loss', 'Բազմաթիվ ծառայությունների անվտանգության խաթարում', 'Երկու և ավելի ծառայություններում (օրինակ՝ Google + Facebook)', 5),
        
        # Device control loss category
        ('device_control_loss', 'Չարամիտ ծրագրի տեղադրում', 'Keylogger, spyware, RAT', 1),
        ('device_control_loss', 'Չարտոնված հեռակա մուտք', 'Չարտոնված հեռակա մուտք սարքի վրա', 2),
        ('device_control_loss', 'Տվյալների ոչնչացում/փոխում', 'Տվյալների ոչնչացում կամ փոխում սարքում', 3),
        ('device_control_loss', 'Տվյալների գաղտնագրում (ransomware)', 'Սարքի տվյալների գաղտնագրման հետևանքով ոչնչացում', 4),
        ('device_control_loss', 'Սարքի կորուստ/գողություն', 'Կիբեռհարձակումով համակցված', 5),
        
        # Psychological damage category
        ('psychological_damage', 'Հոգեբանական ճնշում/շանտաժ', 'Հոգեբանական ճնշում, սպառնալիքներ կամ շանտաժ', 1),
        ('psychological_damage', 'Կիբեռբուլլինգ/վիրավորանք', 'Անձնական վիրավորանք, թշնամանք', 2),
        ('psychological_damage', 'Համբավի վնասում/վարկաբեկում', 'Ֆեյք հարթակում, սոց. ցանցերում', 3),
        ('psychological_damage', 'Կեղծ հաշվի ստեղծում իմ անունով', 'Վնաս հասցնելու նպատակով', 4),
        ('psychological_damage', 'Սոցիալական/ընտանեկան խնդիրներ', 'Կիբերհարձակումների հետևանքով', 5),
        
        # No damage category
        ('incident_no_damage', 'Սեղմել եմ կասկածելի հղման վրա, վնաս չկա', 'Բայց վնաս չի եղել', 1),
        ('incident_no_damage', 'Բացել եմ կասկածելի նամակ', 'Բացել եմ կասկածելի նամակ կամ կցորդ', 2),
        ('incident_no_damage', 'Տվյալ եմ տրամադրել, վնաս չկա', 'Բայց վնաս չի եղել', 3),
        ('incident_no_damage', 'Կանխատեսել եմ ռիսկը, առանց հետևանքների', 'Վնաս չեմ զգացել, կանխատեսել եմ ռիսկը', 4),
        
        # Other damage category
        ('other_damage', 'Այլ վնաս', 'Խնդրում եմ մանրամասնել ստորև', 1),
    ]
    
    created_count = 0
    for category, name, description, order in damage_types_data:
        damage_type, created = DamageType.objects.get_or_create(
            name=name,
            defaults={
                'category': category,
                'description': description,
                'order': order,
                'is_active': True
            }
        )
        if created:
            print(f"✅ Created: {damage_type.name}")
            created_count += 1
        else:
            print(f"⚠️  Already exists: {damage_type.name}")
    
    total = DamageType.objects.count()
    print(f"🎉 Total damage types: {total} (Created: {created_count})")

if __name__ == "__main__":
    create_damage_types()
