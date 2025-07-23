from django import template

register = template.Library()

@register.filter
def get_letter(index):
    """Convert a number to a letter (1=A, 2=B, etc.)"""
    return chr(64 + index) if 1 <= index <= 26 else str(index)

@register.filter
def multiply(value, arg):
    """Multiply the value by the argument"""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return 0

@register.filter
def intdiv(value, arg):
    """Integer division of value by arg"""
    try:
        return int(value) // int(arg)
    except (ValueError, TypeError, ZeroDivisionError):
        return 0

@register.filter
def get_range(value):
    """Return a range from 1 to value"""
    try:
        return range(1, int(value) + 1)
    except (ValueError, TypeError):
        return range(0)

@register.filter
def add(value, arg):
    """Add the arg to the value"""
    try:
        return float(value) + float(arg)
    except (ValueError, TypeError):
        return value