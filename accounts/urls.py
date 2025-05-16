from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import *

urlpatterns = [
    # Authentification
    path('signup/', signup_view, name='signup'),
    path('send-verification-code/', send_verification_code, name='send_verification_code'),
    path('get_salt/', get_salt_view, name='get_salt'),
    path('get_salt_session/', get_salt_session_view, name='get_salt_session'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('search_users/', search_users, name='search_users'),
    # Tableau de bord
    path('dashboard/', dashboard_view, name='dashboard'),
    path('call/', call_view, name='call'),
    path('get-message-count/', get_message_count, name='get_message_count'),
    # Clés et chiffrement
    path('get_secret_key/', get_secret_key, name='get_secret_key'),
    path('get-public-key/', get_public_key, name='get_public_key'),
    path('encrypt/', chiffrer_view, name='chiffrer'),
    path('dcrypt/', dechiffrer_view, name='dechiffrer'),
    
    # Messagerie
    path('message/', message_view, name='message'),
    path('dechf/', dech_view, name='dechf'),
    path('send-message/', send_message_view, name='send_message'),
    path('chat/', conversation_view, name='conversation'),
    path('chat/<str:receiver>/', chat_view, name='chat'),
    path('chatt/', chat_viewsd, name='chatting'),
    path('chat/<str:receiver>/msg/', get_crypted_ajax, name='get_crypted_ajax'),
    path('chat/<str:receiver>/messages/', get_messages_ajax, name='get_messages_ajax'),
    path('sendmessagecrypted/', save_crypted, name='save_crypted'),
    
    # Annuaire et contacts
    path('annuaire/', annuaire_view, name='annuaire'),
    path('move-to-category/', move_to_category, name='move_to_category'),
    path('get-conversations/', get_conversations, name='get_conversations'),
    path('get-users-in-category/', get_users_in_category, name='get_users_in_category'),
    path('get_all_crypted_messages/', get_all_crypted_messages, name='get_all_crypted_messages'),
    path('update_encrypted_message/<int:message_id>/', update_encrypted_message, name='update_encrypted_message'),
     path('update_password/', update_password_and_keys, name='update_password'),

    # Profil utilisateur
    path('profil/', profil_view, name='profil'),
    path('profile/<str:username>/', view_profile, name='view_profile_with_username'),
    path('edit-profile/', edit_profile_view, name='edit_profil'),
]

# Ajout des URLs pour les fichiers média en mode développement
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)