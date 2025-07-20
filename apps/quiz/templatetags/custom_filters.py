from django import template

register = template.Library()

@register.filter
def get_letter(value):
    """
    Number to letter converter: 1 -> A, 2 -> B, etc.
    """
    try:
        value = int(value)
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if 1 <= value <= len(letters):
            return letters[value - 1]
        else:
            return ""
    except (ValueError, TypeError):
        return ""
