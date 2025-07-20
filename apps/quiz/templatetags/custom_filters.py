from django import template

register = template.Library()

@register.filter
def get_letter(index):
    """Convert a number to a letter (1=A, 2=B, etc.)"""
    return chr(64 + index) if 1 <= index <= 26 else str(index)

@register.filter
def multiply(value, arg):
    """Multiply the value by the argument"""
    return value * arg