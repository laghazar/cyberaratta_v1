from django import template

register = template.Library()

@register.filter(name='multiply')
def multiply(value, arg):
    """Բազմապատկում է տրված արժեքը որևէ արգումենտով"""
    try:
        return int(value) * int(arg)
    except (ValueError, TypeError):
        return value
        
@register.filter(name='get_letter')
def get_letter(value):
    """Վերադարձնում է թվին համապատասխան տառը (1->A, 2->B, ...)"""
    try:
        num = int(value)
        return chr(64 + num) if 1 <= num <= 26 else str(num)
    except (ValueError, TypeError):
        return value

@register.filter(name='get_range')
def get_range(value):
    """Ստեղծում է range օբյեկտ տրված արժեքի համար"""
    try:
        return range(1, int(value) + 1)
    except (ValueError, TypeError):
        return range(0)
        
@register.filter(name='intdiv')
def intdiv(value, arg):
    """Կատարում է ամբողջթվային բաժանում"""
    try:
        return int(value) // int(arg)
    except (ValueError, TypeError):
        return value