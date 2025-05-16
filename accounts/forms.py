from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class SignupForm(forms.ModelForm):
    # User fields
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    
    # Cryptographic fields (must match JS)
    derived_key = forms.CharField(required=True)  # Hex string
    salt = forms.CharField(required=True)  # Hex string
    public_key = forms.CharField(required=True)  # Base64 string
    encrypted_private_key = forms.CharField(required=True)  # Base64 string
    salt_session = forms.CharField(required=True)  # Hex string
    
    # Verification code field
    verification_code = forms.CharField(required=False)  # Not required in model, validated in view

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email']