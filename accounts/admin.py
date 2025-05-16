from django.contrib import admin
from .models import *
import base64
class UserKeyAdmin(admin.ModelAdmin):
    list_display = ('user', 'public_key')
    search_fields = ('user__username',)
    readonly_fields = ('public_key',)



class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'timestamp', 'formatted_encrypted_message','formatted_encrypted_cle','formatted_encrypted_file','filetype','filename')
    search_fields = ('sender__username', 'receiver__username')
    list_filter = ('sender', 'receiver', 'timestamp')  # Add filters for sender, receiver, and timestamp
    ordering = ['-timestamp']  # Order by most recent messages first

    def formatted_encrypted_message(self, obj):
        """Format the encrypted message for better readability."""
        max_length = 50  # Limit the number of characters displayed
        if len(obj.encrypted_message) > max_length:
            return f"{obj.encrypted_message[:max_length]}..."
        return obj.encrypted_message

    formatted_encrypted_message.short_description = 'Encrypted Message'  # Column header name
    formatted_encrypted_message.admin_order_field = 'encrypted_message'  # Allow sorting by this field

    def formatted_encrypted_cle(self, obj):
        """Format the encrypted message for better readability."""
        max_length = 50  # Limit the number of characters displayed
        if len(obj.encrypted_cle) > max_length:
            return f"{obj.encrypted_cle[:max_length]}..."
        return obj.encrypted_cle
    
    formatted_encrypted_cle.short_description = 'Encrypted cle'
    formatted_encrypted_cle.admin_order_field = 'encrypted_cle'

    def formatted_encrypted_file(self, obj):
        """Format the encrypted file for better readability."""
        if not obj.encrypted_file:  # Handles None
            return '-'
        try:
            file_base64 = base64.b64encode(obj.encrypted_file).decode('utf-8')
            max_length = 50
            if len(file_base64) > max_length:
                return f"{file_base64[:max_length]}..."
            return file_base64
        except Exception:
            return '[Invalid bytes]'

    formatted_encrypted_file.short_description = 'Encrypted File'
    formatted_encrypted_file.admin_order_field = 'encrypted_file'

class MessagecryptedAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver','owner', 'timestamp', 'formatted_encrypted_message','formatted_encrypted_file','filetype','filename','formatted_encrypted_message_self','sig')
    search_fields = ('sender__username', 'receiver__username')
    list_filter = ('sender', 'receiver', 'timestamp')  # Add filters for sender, receiver, and timestamp
    ordering = ['-timestamp']  # Order by most recent messages first

    def formatted_encrypted_message(self, obj):
        """Format the encrypted message for better readability."""
        max_length = 50  # Limit the number of characters displayed
        if len(obj.encrypted_message) > max_length:
            return f"{obj.encrypted_message[:max_length]}..."
        return obj.encrypted_message

    formatted_encrypted_message.short_description = 'Encrypted Message'  # Column header name
    formatted_encrypted_message.admin_order_field = 'encrypted_message'  # Allow sorting by this field

    def formatted_encrypted_file(self, obj):
        """Format the encrypted file for better readability."""
        if not obj.encrypted_file:  # Handles None
            return '-'
        try:
            file_base64 = base64.b64encode(obj.encrypted_file).decode('utf-8')
            max_length = 50
            if len(file_base64) > max_length:
                return f"{file_base64[:max_length]}..."
            return file_base64
        except Exception:
            return '[Invalid bytes]'

    formatted_encrypted_file.short_description = 'Encrypted File'
    formatted_encrypted_file.admin_order_field = 'encrypted_file'

    def formatted_encrypted_message_self(self, obj):
        """Format the encrypted message for better readability."""
        max_length = 50  # Limit the number of characters displayed
        if len(obj.self_crypted) > max_length:
            return f"{obj.self_crypted[:max_length]}..."
        return obj.self_crypted

    formatted_encrypted_message_self.short_description = 'Encrypted Message self'  # Column header name
    formatted_encrypted_message_self.admin_order_field = 'self_crypted'  # Allow sorting by this field

admin.site.register(UserKey, UserKeyAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(EncryptedMessage, MessagecryptedAdmin)