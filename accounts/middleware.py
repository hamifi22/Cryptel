from django.utils import timezone
from .models import UserDevice
import user_agents
import geoip2.database
from django.conf import settings
import os

class DeviceTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        response = self.get_response(request)
        
        if request.user.is_authenticated:
            user_agent_string = request.META.get('HTTP_USER_AGENT', '')
            ip_address = self.get_client_ip(request)
            
            # Parse user agent
            ua = user_agents.parse(user_agent_string)
            
            # Get location (requires GeoIP2 database)
            location = self.get_location(ip_address)
            
            # Create or update device
            device_name = f"{ua.device.family} {ua.os.family} {ua.browser.family}"
            device, created = UserDevice.objects.get_or_create(
                user=request.user,
                user_agent=user_agent_string,
                defaults={
                    'device_name': device_name,
                    'browser': ua.browser.family,
                    'os': ua.os.family,
                    'ip_address': ip_address,
                    'location': location,
                }
            )
            
            if not created:
                device.ip_address = ip_address
                device.location = location
                device.last_login = timezone.now()
                device.save()
                
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def get_location(self, ip_address):
        try:
            geoip_path = os.path.join(settings.BASE_DIR, 'GeoLite2-City.mmdb')
            with geoip2.database.Reader(geoip_path) as reader:
                response = reader.city(ip_address)
                return f"{response.city.name}, {response.country.name}"
        except:
            return "Unknown location"