from django import forms

class URLCheckForm(forms.Form):
    input_text = forms.CharField(max_length=500, label="URL կամ Էլ. փոստ")