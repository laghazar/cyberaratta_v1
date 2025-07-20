from django import template
import string

register = template.Library()

@register.filter
def get_range(value):
    """Returns a range from 1 to value"""
    return range(1, value + 1)

@register.filter
def get_letter(value):
    """Convert number to letter (1=A, 2=B, etc.)"""
    return string.ascii_uppercase[value - 1]

@register.filter
def get_points(value):
    """Calculate points for millionaire question based on position"""
    return value * 100

@register.filter
def multiply(value, arg):
    """Multiply the value by the argument"""
    return value * arg

@register.filter
def intdiv(value, arg):
    """Integer division"""
    return value // arg