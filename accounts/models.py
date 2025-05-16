from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f'Profil de {self.user.username}'

# Signal pour créer automatiquement un profil quand un utilisateur est créé
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()

class UserKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    private_key = models.TextField(default="")
    salt = models.TextField(default="")
    category = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"Clé publique pour {self.user.username}"

class UserAuth(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    derived_key = models.TextField(default="")
    salt = models.TextField(default="")        
    
    def __str__(self):
        return f"Clé publique pour {self.user.username}"

class UserDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    device_name = models.CharField(max_length=100)
    browser = models.CharField(max_length=100, blank=True, null=True)
    os = models.CharField(max_length=100, blank=True, null=True)
    ip_address = models.GenericIPAddressField()
    last_login = models.DateTimeField(auto_now=True)
    location = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    user_agent = models.TextField(blank=True, null=True)
    current_session = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-last_login']
    
    def __str__(self):
        return f"{self.device_name} ({self.user.username})"

class Message(models.Model):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    encrypted_message = models.TextField()
    encrypted_cle = models.TextField(default="")
    encrypted_cle_file = models.TextField(default="")
    timestamp = models.DateTimeField(auto_now_add=True)
    sig = models.TextField(default="")
    hash_m = models.TextField(default="")
    encrypted_file = models.BinaryField(null=True)
    filetype = models.TextField(default="")
    filename = models.TextField(default="")
    sig_file = models.TextField(default="")
    hash_f = models.TextField(default="")
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"Message de {self.sender.username} à {self.receiver.username}"

class EncryptedMessage(models.Model):
    sender = models.ForeignKey(User, related_name='sent_encrypted_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_encrypted_messages', on_delete=models.CASCADE)
    owner = models.ForeignKey(User, related_name='owned_encrypted_messages', on_delete=models.CASCADE, null=True)
    encrypted_message = models.TextField()
    encrypted_file = models.BinaryField(null=True)
    filetype = models.TextField(default="")
    filename = models.TextField(default="")
    timestamp = models.DateTimeField(auto_now_add=True)
    self_crypted = models.TextField(default="")
    sig = models.TextField(default="")

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"Encrypted message from {self.sender.username} to {self.receiver.username}"

class Call(models.Model):
    caller = models.ForeignKey(User, related_name='caller', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='receiver', on_delete=models.CASCADE)
    start_time = models.DateTimeField(auto_now_add=True)
    end_time = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default='initiated')

    def __str__(self):
        return f"{self.caller} -> {self.receiver}"