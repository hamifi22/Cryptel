from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.db.models.functions import Least, Greatest
from django.db.models import Q, Max, F, Value, Case, When
import hashlib
from django.urls import reverse  # Import manquant
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST

from django.contrib.humanize.templatetags.humanize import naturaltime
from django.utils.crypto import pbkdf2
from django.contrib.sessions.models import Session
from django.utils import timezone
import time
from .forms import SignupForm
from .utils import *
from .models import *
from django.conf import settings
from django.contrib.auth import get_user_model
User = get_user_model()
import os
from django.core.mail import send_mail
import uuid
import json
import logging
from django.contrib import messages
import random
import string
from .models import Profile
from django.core.cache import cache




User = get_user_model()

def generate_verification_code(length=6):
    """Generate a random verification code."""
    return ''.join(random.choices(string.digits, k=length))

@csrf_exempt
def send_verification_code(request):
    """Send a verification code to the provided email."""
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method."}, status=405)

    try:
        data = json.loads(request.body)
        email = data.get("email")
        if not email:
            return JsonResponse({"error": "Email is required."}, status=400)

        # Validate email format
        from django.core.validators import validate_email
        try:
            validate_email(email)
        except:
            return JsonResponse({"error": "Invalid email format."}, status=400)

        # Check if email is already registered
        if User.objects.filter(email=email).exists():
            return JsonResponse({"error": "Email is already registered."}, status=400)

        # Rate limiting: Prevent sending too many codes
        cache_key = f"verification_code:{email}"
        request_count = cache.get(cache_key, 0)
        if request_count >= 3:  # Limit to 3 attempts per 5 minutes
            return JsonResponse({"error": "Too many verification requests. Please try again later."}, status=429)

        # Generate and store verification code with timestamp
        verification_code = generate_verification_code()
        request.session['verification_code'] = verification_code
        request.session['email_for_verification'] = email
        request.session['code_timestamp'] = int(time.time())  # Store timestamp
        request.session.modified = True

        # Increment rate limit counter
        cache.set(cache_key, request_count + 1, timeout=300)  # 5-minute timeout

        # Send email
        subject = "Your Verification Code"
        message = f"Your verification code is: {verification_code}\nThis code expires in 10 minutes."
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            return JsonResponse({"message": "Verification code sent successfully."}, status=200)
        except Exception as e:
            return JsonResponse({"error": f"Failed to send email: {str(e)}"}, status=500)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid request data. Expected JSON."}, status=400)
    except Exception as e:
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

def signup_view(request):
    """Handle user signup with verification code and cryptographic keys."""
    if request.method == "POST":
        try:
            form = SignupForm(request.POST)
            if not form.is_valid():
                return JsonResponse({
                    'status': 'error',
                    'errors': form.errors.get_json_data()
                }, status=400)

            # Get verification code and session data
            verification_code = form.cleaned_data.get('verification_code')
            session_code = request.session.get('verification_code')
            session_email = request.session.get('email_for_verification')
            code_timestamp = request.session.get('code_timestamp')

            # Check if verification code has expired (10 minutes)
            if code_timestamp and (int(time.time()) - code_timestamp) > 600:
                request.session.pop('verification_code', None)
                request.session.pop('email_for_verification', None)
                request.session.pop('code_timestamp', None)
                return JsonResponse({
                    'status': 'error',
                    'errors': {'verification_code': ['Verification code has expired. Please request a new one.']}
                }, status=400)

            # Verify the code
            if not session_code or not session_email:
                return JsonResponse({
                    'status': 'error',
                    'errors': {'verification_code': ['No verification code requested. Please request a code first.']}
                }, status=400)

            if verification_code != session_code or form.cleaned_data['email'] != session_email:
                return JsonResponse({
                    'status': 'error',
                    'errors': {'verification_code': ['Invalid verification code or email mismatch.']}
                }, status=400)

            # Get cryptographic parameters
            derived_key_hex = form.cleaned_data['derived_key']
            salt_hex = form.cleaned_data['salt']
            public_key = form.cleaned_data['public_key']
            encrypted_private_key = form.cleaned_data['encrypted_private_key']
            salt2_hex = form.cleaned_data['salt_session']

            # Validate cryptographic parameters
            if not all([derived_key_hex, salt_hex, public_key, encrypted_private_key, salt2_hex]):
                return JsonResponse({
                    'status': 'error',
                    'errors': {'__all__': ['Missing cryptographic parameters.']}
                }, status=400)

            try:
                # Convert hex strings to bytes
                derived_key = bytes.fromhex(derived_key_hex)
                salt = bytes.fromhex(salt_hex)
                salt2 = bytes.fromhex(salt2_hex)
            except ValueError:
                return JsonResponse({
                    'status': 'error',
                    'errors': {'__all__': ['Invalid cryptographic parameters format.']}
                }, status=400)

            # Create user with unusable password
            user = form.save(commit=False)
            user.set_unusable_password()
            user.save()

            # Store authentication materials
            UserAuth.objects.create(
                user=user,
                derived_key=base64.b64encode(derived_key).decode('ascii'),
                salt=base64.b64encode(salt).decode('ascii')
            )

            # Store key materials
            UserKey.objects.create(
                user=user,
                public_key=public_key,
                private_key=encrypted_private_key,
                salt=base64.b64encode(salt2).decode('ascii')
            )

            # Log in the user
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')

            # Clear session data
            request.session.pop('verification_code', None)
            request.session.pop('email_for_verification', None)
            request.session.pop('code_timestamp', None)

            return JsonResponse({
                'status': 'success',
                'redirect_url': '/annuaire/'  # Use reverse('annuaire') in production
            }, status=200)

        except Exception as e:
            return JsonResponse({
                'status': 'error',
                'errors': {'__all__': [f'Server error: {str(e)}']}
            }, status=500)

    # GET request: Render signup form
    return render(request, 'signup.html', {'form': SignupForm()})

def get_salt_session_view(request):
    username = request.GET.get('username')
    try:
        user = User.objects.get(username=username)
        user_auth = UserKey.objects.get(user=user)
        print(user_auth.salt)

        return JsonResponse({'salt': user_auth.salt})

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    except UserAuth.DoesNotExist:
        return JsonResponse({'error': 'UserAuth entry not found'}, status=404)
    
def get_salt_view(request):
    username = request.GET.get('username')
    try:
        user = User.objects.get(username=username)
        user_auth = UserAuth.objects.get(user=user)
        print(user_auth.salt)

        return JsonResponse({'salt': user_auth.salt})

    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)

    except UserAuth.DoesNotExist:
        return JsonResponse({'error': 'UserAuth entry not found'}, status=404)
@csrf_exempt  
def update_password_and_keys(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = request.user
            derived_key_hex = data.get('new_derived_key')
            salt_hex = data.get('new_salt')
            salt2_hex = data.get('new_salt2')
            derived_key = bytes.fromhex(derived_key_hex)
            salt = bytes.fromhex(salt_hex)
            salt2 = bytes.fromhex(salt2_hex)
            Sb = data.get('Sb')
          
            
            print(base64.b64encode(salt).decode('ascii'))
            # Update UserAuth with new derived key and salt
            user_auth,created  = UserAuth.objects.get_or_create(user=user)
            user_auth.derived_key =base64.b64encode(derived_key).decode('ascii')
            user_auth.salt = base64.b64encode(salt).decode('ascii')
            user_auth.save()

            user_K,created  = UserKey.objects.get_or_create(user=user)
            user_K.salt = base64.b64encode(salt2).decode('ascii')
            user_K.private_key = Sb
            user_K.save()

            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error'}, status=405)

@csrf_exempt  
def login_view(request):
    try:
        # Parsing incoming JSON request body
        data = json.loads(request.body)
        username = data.get('username')
        user = User.objects.get(username=username)

        derived_password_hex = data.get('derived_password')
        derived_password_byte = bytes.fromhex(derived_password_hex)
        derived_password=base64.b64encode(derived_password_byte).decode('ascii')
        # Check for missing credentials
        if not username or not derived_password:
            return JsonResponse({'status': 'error', 'message': 'Missing credentials'}, status=400)

        # Attempt to get the user auth object based on username
        try:
            user_auth = UserAuth.objects.get(user__username=username)
        except UserAuth.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)

        # Check if the derived password matches
        if user_auth.derived_key == derived_password:
            login(request, user)
            return JsonResponse({
                'status': 'success',
                'redirect': '/accounts/annuaire/',  # You could redirect to a dashboard or another page
            })
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid credentials'}, status=403)

    except json.JSONDecodeError:
         return render(request, 'login.html')  # Ensure your template is being loaded here
   

def dashboard_view(request):
    return render(request, 'dashboard.html')

def get_secret_key(request):
    try:
        current_user = request.user
        # Retrieve the conversation object
        keys = UserKey.objects.get(user=current_user)
        
        # Get the secret key (encrypted_cle)
        secret_key = keys.private_key
        
        # Return the secret key as a JSON response
        return JsonResponse({'secret_key': secret_key})
    except Message.DoesNotExist:
        return JsonResponse({'error': 'Conversation not found'}, status=404)

def logout_view(request):
    logout(request)
    return redirect('login')

def message_view(request):
    return render(request, 'message.html')

def annuaire_view(request):
    user_keys = UserKey.objects.select_related('user').all()
    return render(request, 'annuaire.html', {'user_keys': user_keys})

@csrf_exempt
def chiffrer_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            message = data.get('message')
            public_key = data.get('public_key')
            private_key=data.get('private_key')
            file_b64 = data.get('file_data')
     
            filename = data.get('filename')
            content_type = data.get('content_type')
            ec= ECDSA(P256params)
            if file_b64 and message:
                encrypted_file, c2_file = chiffrer_msg(file_b64, public_key)
                signature_file, hash_value_f = ec.Ecdsa_sign(file_b64, private_key)
                encrypted_message, c2 = chiffrer_msg(message, public_key)
                signature, hash_value = ec.Ecdsa_sign(message, private_key)
                return JsonResponse({
                'encrypted_file': encrypted_file,
                'c2_file': c2_file,
                'signature_file': signature_file,
                'hash_value_f':  int(hash_value_f),
                'Fname': filename,
                'Ftype': content_type,
                'encrypted_message': encrypted_message,
                'c2': c2,
                'signature': signature,
                'hash_value':  int(hash_value),
                })

            elif file_b64:
                content = file_b64
                encrypted_file, c2 = chiffrer_msg(content, public_key)
                signature, hash_value = ec.Ecdsa_sign(content, private_key)
                return JsonResponse({
                'encrypted_file': encrypted_file,
                'c2_file': c2,
                'signature_file': signature,
                'hash_value_f':  int(hash_value),
                'Fname': filename,
                'Ftype': content_type,
                })
            elif message:
                content = message
                encrypted_message, c2 = chiffrer_msg(content, public_key)
                signature, hash_value = ec.Ecdsa_sign(content, private_key)
                return JsonResponse({
                'encrypted_message': encrypted_message,
                'c2': c2,
                'signature': signature,
                'hash_value':  int(hash_value),

                })
            else:
                return JsonResponse({'error': 'No input provided'}, status=400)

            # Chiffrer le message



            # Retourner les deux valeurs
           

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

def get_public_key(request):
    if request.method == 'GET':
        username = request.GET.get('username', None)
        if username:
            try:
                user = User.objects.get(username=username)
                user_key = UserKey.objects.get(user=user)
                return JsonResponse({'public_key': user_key.public_key})
            except (User.DoesNotExist, UserKey.DoesNotExist):
                return JsonResponse({'public_key': 'Clé publique introuvable.'}, status=404)
    return JsonResponse({'public_key': 'Nom d’utilisateur requis.'}, status=400)

@csrf_exempt
def send_message_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            encrypted_message = data.get('encrypted_message')
            c2 = data.get('c2')  
            signature = data.get('signature')  
            hash_value = data.get('hash_value')
            encrypted_file = data.get('encrypted_file')
            print(encrypted_message)
            filetype= data.get('filetype')
            filename= data.get('filename')
            c2_f = data.get('c2_f')  
            signature_f = data.get('signature_f')  
            hash_value_f = data.get('hash_value_f')
            user = User.objects.get(username=username)
            if(encrypted_message):
                encrypted_file_bytes = None
                Message.objects.create(
                sender=request.user,
                encrypted_file=encrypted_file_bytes,
                receiver=user,
                encrypted_message=encrypted_message,
                encrypted_cle=c2,
                sig=signature,
                hash_m=hash_value,
   
            )
            else:
                encrypted_bytes = base64.b64decode(encrypted_file)
                Message.objects.create(
                sender=request.user,
                receiver=user,
                encrypted_file=encrypted_bytes,
                encrypted_cle_file=c2_f,
                sig_file=signature_f,
                hash_f=hash_value_f,
                filetype=filetype,
                filename=filename,
                )           

            return JsonResponse({'success': 'Message envoyé avec succès!'})
        except User.DoesNotExist:
            return JsonResponse({'error': 'Utilisateur introuvable.'}, status=404)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)



@login_required
def get_message_count(request):
    last_check = request.session.get('last_message_check', None)
    current_time = timezone.now()
    
    query = Message.objects.filter(receiver=request.user)
    if last_check:
        query = query.filter(timestamp__gt=last_check)
    
    new_messages = [
        {
            'id': message.id,
            'sender': message.sender.username,
            'timestamp': naturaltime(message.timestamp),  # e.g., "5 minutes ago"
            'timestamp_iso': message.timestamp.isoformat()  # For session comparison
        }
        for message in query
    ]
    
    request.session['last_message_check'] = current_time.isoformat()
    
    total_count = Message.objects.filter(receiver=request.user).count()  # Adjust if using is_read
    
    return JsonResponse({
        'message_count': total_count,
        'new_messages': new_messages
    })

def conversation_view(request):
     current_user = request.user

    # Combine sent and received messages
     conversations = (
        EncryptedMessage.objects
        .filter(Q(sender=current_user) | Q(receiver=current_user))
        .values('sender', 'receiver')
        .annotate(last_message_id=models.Max('id'))
        .values_list('sender', 'receiver', 'last_message_id', named=True)
    )

    # Prepare the data for the template
     conversation_data = []
     for entry in conversations:
        other_user_id = entry.sender if entry.sender != current_user.id else entry.receiver
        other_user = User.objects.get(id=other_user_id)
        last_message = Message.objects.get(id=entry.last_message_id)
        conversation_data.append({
            'user': other_user,
            'last_message': last_message.encrypted_message,
            'timestamp': last_message.timestamp,
            'file': last_message.encrypted_file,
            'filetype': last_message.filetype,
            'filename': last_message.filename
        })

     return render(request, 'conversations.html', {'conversations': conversation_data})

def chat_view(request, receiver):
    receiver_user = get_object_or_404(User, username=receiver)
    messages = Message.objects.filter(
        sender=request.user, receiver=receiver_user
    ) | Message.objects.filter(
        sender=receiver_user, receiver=request.user
    ).order_by("timestamp")

    return render(request, "conversation.html", {
        "receiver": receiver_user,
        "messages": messages,
    })

def get_messages_ajax(request, receiver):
    receiver_user = get_object_or_404(User, username=receiver)
    since = request.GET.get("since")

    # Base queryset (all messages between both users)
    queryset = Message.objects.filter(
        (Q(sender=request.user) & Q(receiver=receiver_user)) |
        (Q(sender=receiver_user) & Q(receiver=request.user))
    )

    # Filter only messages newer than "since" if provided
    if since:
        try:
            since_dt = parse_datetime(since)
            if since_dt:
                queryset = queryset.filter(timestamp__gt=since_dt)
        except:
            pass  # fallback to no filtering

    queryset = queryset.order_by("timestamp")

    messages_data = [
        {
            "sender": msg.sender.username,
            "receiver": msg.receiver.username,
            "text": msg.encrypted_message,
            "file": msg.encrypted_file,
            "filename": msg.filename,
            "timestamp": msg.timestamp.strftime("%d %b %H:%M"),
            "timestamp_raw": msg.timestamp.isoformat()  # Send raw for future filtering
        }
        for msg in queryset
    ]

    return JsonResponse({"messages": messages_data})


def get_crypted_ajax(request, receiver):
    receiver_user = get_object_or_404(User, username=receiver)
    since = request.GET.get("since")

    # Base queryset (all messages between both users)
    queryset = EncryptedMessage.objects.filter(
        (Q(sender=request.user) & Q(receiver=receiver_user) & Q(owner=request.user)) |
        (Q(sender=receiver_user) & Q(receiver=request.user) & Q(owner=request.user)) 
    ).distinct()

    # Filter only messages newer than "since" if provided
    if since:
        try:
            since_dt = parse_datetime(since)
            if since_dt:
                queryset = queryset.filter(timestamp__gt=since_dt)
        except:
            pass  # fallback to no filtering

    queryset = queryset.order_by("timestamp")
    print(f"Total messages fetched: {queryset.count()}")
    for msg in queryset:
     print(f"Message ID: {msg.id}, Timestamp: {msg.timestamp}")
    messages_data = []
    for msg in queryset:
      file = None
      if msg.encrypted_file:
        file = base64.b64encode(msg.encrypted_file).decode('utf-8')

      messages_data.append({
        "id": msg.id,  # Add this

        "sender": msg.sender.username,
        "receiver": msg.receiver.username,
        "text": msg.encrypted_message,
        "sig": msg.sig,
        "file": file,
        "filetype":msg.filetype,
        "filename": msg.filename,
        "timestamp": msg.timestamp.strftime("%d %b %H:%M"),
        "timestamp_raw": msg.timestamp.isoformat()
      })


    return JsonResponse({"messages": messages_data})


def get_all_crypted_messages(request):
    queryset = EncryptedMessage.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user),
        owner=request.user
    ).distinct().order_by("-timestamp")

    messages_data = []
    for msg in queryset:
        file = None
        if msg.encrypted_file:
            file = base64.b64encode(msg.encrypted_file).decode('utf-8')

        messages_data.append({
            "id": msg.id,
            "text": msg.encrypted_message,
            "file": file,
        })

    return JsonResponse({"messages": messages_data})


@csrf_exempt
def update_encrypted_message(request, message_id):
    if request.method == 'POST':
        try:
            message = EncryptedMessage.objects.get(id=message_id, owner=request.user)
            data = json.loads(request.body)
            typee= data['typee']
            encrypted_data = data['encryptedData']
            if typee == 'message':
                message.encrypted_message = encrypted_data
            if typee == 'file':
                message.encrypted_file = base64.b64decode(encrypted_data)
            
            message.save()
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    return JsonResponse({'status': 'error'}, status=405)

def dech_view(request):
    return render(request, 'dechifferment.html')
@csrf_exempt  
def save_crypted(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            encrypted_message = data.get('message')
            sig = data.get('sig')
            encrypted_file = data.get('file')

            filetype= data.get('content_type')
            filename= data.get('filename')
            sender_username = data.get('sender')
            receiver_username = data.get('receiver')
            sender = User.objects.get(username=sender_username)
            receiver = User.objects.get(username=receiver_username)

            if encrypted_message and encrypted_file:
                encrypted_bytes = base64.b64decode(encrypted_file)

                if (sig):
                   EncryptedMessage.objects.create(
                sender=sender,
                receiver=receiver,
                encrypted_message=encrypted_message,
                encrypted_file=encrypted_bytes,
                owner = request.user,
                filetype=filetype,
                filename=filename,          
                sig=sig,
                )
                else:
                    EncryptedMessage.objects.create(
                sender=sender,
                receiver=receiver,
                encrypted_message=encrypted_message,
                encrypted_file=encrypted_bytes,
                owner = request.user,
                filetype=filetype,
                filename=filename,
                                )

                   
            elif(encrypted_message):
                encrypted_file_bytes = None
                if(sig):
                 EncryptedMessage.objects.create(
                sender=sender,
                receiver=receiver,
                encrypted_message=encrypted_message,   
                sig=sig,
                encrypted_file=encrypted_file_bytes,

                owner = request.user
                )
                else:
                    EncryptedMessage.objects.create(
                sender=sender,
                receiver=receiver,
                encrypted_file=encrypted_file_bytes,
                encrypted_message=encrypted_message,   
                owner = request.user
                )
            else:
                encrypted_bytes = base64.b64decode(encrypted_file)

                if(sig):
                 EncryptedMessage.objects.create(
                    sender=sender,
                    receiver=receiver,
                    encrypted_file=encrypted_bytes,
                    filetype=filetype,
                    filename=filename,
                    sig=sig,
                    owner = request.user
                   )  
                else : 
                    EncryptedMessage.objects.create(
                    sender=sender,
                    receiver=receiver,
                    encrypted_file=encrypted_bytes,
                    filetype=filetype,
                    filename=filename,
                    owner = request.user
                   )  
            return JsonResponse({'success': 'Message envoyé avec succès!'})
        except User.DoesNotExist:
           return JsonResponse({'error': 'Utilisateur introuvable.'}, status=404)
        except Exception as e:
          return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

def chat_viewsd(request):
    # Try to find the latest message involving the current user
    last_message = EncryptedMessage.objects.filter(
        sender=request.user
    ).order_by('-timestamp').first()

    if not last_message:
        last_message = EncryptedMessage.objects.filter(
            receiver=request.user
        ).order_by('-timestamp').first()

    if last_message:
        # Determine the "other" user
        if last_message.sender == request.user:
            other_user = last_message.receiver
        else:
            other_user = last_message.sender

        return redirect('chat', receiver=other_user.username)

    # No previous messages: you can redirect somewhere else or show a message
    return render(request, "annuaire.html")

@csrf_exempt  

def dechiffrer_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            receiver =data.get('receiver')
            receiver_user = User.objects.get(username=receiver)


            # Get only messages for the current user
            messages = Message.objects.filter(sender=receiver_user, receiver=request.user)     
            decrypted_messages = []
            
            for message in messages:
                try:

                    c2 = message.encrypted_cle
                    c2_f = message.encrypted_cle_file
                    sender = message.sender
                    sig = message.sig
                    sig_f = message.sig_file            
                    file_data = message.encrypted_file


                    message_crypt = message.encrypted_message
                    ec = ECDSA(P256params)
                    
                    decrypted_data = {
                        'id': message.id,
                        'sender': sender.username,  # or any sender identifier
                        'timestamp': message.timestamp.isoformat() if message.timestamp else None,
                    }
                    
                    decrypted_successfully = False
                    
                    if message_crypt:

                        messages.delete()
                        decrypted_data.update({
                            'message': message_crypt,
                            'c2':c2,
                            'sig':sig,
                            'type': 'text'
                            })
                        decrypted_successfully = True
                        
                    if file_data:
                        file = base64.b64encode(file_data).decode('utf-8')



                        decrypted_data.update({
                            'file_content': file,
                            'c2_f':c2_f,
                            'filename': message.filename,
                            'content_type': message.filetype,
                            'sig_f': sig_f,
                            'type': 'file'
                          })
                        messages.delete()
                        decrypted_successfully = True
                        
                    if decrypted_successfully:
                        decrypted_messages.append(decrypted_data)
                        
                    
                except Exception as e:
                    # Skip messages that can't be decrypted or have errors
                    continue
            
            
            
            return JsonResponse({
                'messages': decrypted_messages,
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

@require_POST
@csrf_exempt
def move_to_category(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            category = data.get('category')
            
            # Ici votre logique pour mettre à jour la catégorie
            # Exemple:
            user_key = UserKey.objects.get(user__username=username)
            user_key.category = None if category == "Non classé" else category
            user_key.save()
            
            return JsonResponse({'success': True})
            
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Méthode non autorisée'}, status=405)

def get_users_in_category(request):
    category = request.GET.get('category', 'Tous')
    
    if category == 'Tous':
        users = UserKey.objects.select_related('user').all()
    else:
        if category == 'Non classé':
            users = UserKey.objects.filter(category__isnull=True)
        else:
            users = UserKey.objects.filter(category=category)

    users_data = []
    for uk in users:
        user_data = {
            'username': uk.user.username,
            'public_key': uk.public_key,
            'category': uk.category,
            'profil': None,  # Default value if no profile
            'url_profil': None  # Default value if no profile
        }
        
        # Add profile information if it exists
        if hasattr(uk.user, 'profile') and uk.user.profile.profile_picture:
            user_data['profil'] = uk.user.profile.profile_picture.name
            user_data['url_profil'] = uk.user.profile.profile_picture.url
        
        users_data.append(user_data)
    
    return JsonResponse({'users': users_data})
def annuaire_view(request):
    # Récupérer tous les UserKey avec leurs utilisateurs associés
    user_keys = UserKey.objects.select_related('user').all()
    
    # Créer un dictionnaire pour catégoriser les utilisateurs
    categorized_users = {
        'Travail': [],
        'Personnel': [],
        'Famille': [],
        'Amis': [],
        'Non classé': []
    }
    
    # Remplir les catégories
    for user_key in user_keys:
        if user_key.category in categorized_users:
            categorized_users[user_key.category].append(user_key)
        else:
            categorized_users['Non classé'].append(user_key)
    
    # Ajouter une entrée "Tous" qui contient tous les utilisateurs
    categorized_users['Tous'] = list(user_keys)
    
    return render(request, 'annuaire.html', {
        'user_keys': user_keys,
        'categorized_users': categorized_users,
    })

@login_required
def get_conversations(request):
    current_user = request.user

    # Normalize sender and receiver: always keep the smallest ID as 'user1'
    conversations = (
        EncryptedMessage.objects
        .filter(Q(sender=current_user) | Q(receiver=current_user))
        .annotate(
            user1=Least('sender', 'receiver'),
            user2=Greatest('sender', 'receiver')
        )
        .values('user1', 'user2')
        .annotate(last_message_id=Max('id'))
    )

    # Prepare JSON data
    conversation_data = []
    for entry in conversations:
        last_message = EncryptedMessage.objects.get(id=entry['last_message_id'])

        # Determine who is the other user
        other_user_id = (
            entry['user1'] if entry['user1'] != current_user.id else entry['user2']
        )
        other_user = User.objects.get(id=other_user_id)
        
        # Get profile picture URL if exists
        profile_pic_url = None
        if hasattr(other_user, 'profile') and other_user.profile.profile_picture:
            profile_pic_url = other_user.profile.profile_picture.url

        conversation_data.append({
            'user_id': other_user.id,
            'username': other_user.username,
            'profile_pic_url': profile_pic_url,
            'last_message': last_message.encrypted_message,
            'timestamp': last_message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })

    return JsonResponse({'conversations': conversation_data})

def profil_view(request, username=None):
        # Si aucun username n'est spécifié, afficher le profil de l'utilisateur connecté
    if not username:
        user = request.user
    else:
        user = get_object_or_404(User, username=username)
    
    # Récupérer les informations supplémentaires de l'utilisateur
    try:
        user_key = UserKey.objects.get(user=user)
        public_key = user_key.public_key
    except UserKey.DoesNotExist:
        public_key = None
    
    # Récupérer les messages récents (les 3 derniers)
    recent_messages = Message.objects.filter(
        models.Q(sender=user) | models.Q(receiver=user)
    ).order_by('-timestamp')[:3]
    
    # Récupérer les messages chiffrés récents (les 3 derniers)
    recent_encrypted_messages = EncryptedMessage.objects.filter(
        models.Q(sender=user) | models.Q(receiver=user)
    ).order_by('-timestamp')[:3]
    
    # Combiner les activités récentes
    recent_activities = []
    
    # Ajouter les messages normaux
    for msg in recent_messages:
        if msg.sender == user:
            activity = {
                'action': f"Sent message to {msg.receiver.username}",
                'date': msg.timestamp
            }
        else:
            activity = {
                'action': f"Received message from {msg.sender.username}",
                'date': msg.timestamp
            }
        recent_activities.append(activity)
    
    # Ajouter les messages chiffrés
    for msg in recent_encrypted_messages:
        if msg.sender == user:
            activity = {
                'action': f"Sent encrypted message to {msg.receiver.username}",
                'date': msg.timestamp
            }
        else:
            activity = {
                'action': f"Received encrypted message from {msg.sender.username}",
                'date': msg.timestamp
            }
        recent_activities.append(activity)
    
    # Trier les activités par date (du plus récent au plus ancien)
    recent_activities.sort(key=lambda x: x['date'], reverse=True)
    # Ne garder que les 3 plus récentes
    recent_activities = recent_activities[:3]
    
    context = {
        'user_profile': user,
        'public_key': public_key,
        'recent_activities': recent_activities,
    }
    
    return render(request, 'profil.html', context)



def view_profile(request, username=None):
    # Si aucun username n'est spécifié, afficher le profil de l'utilisateur connecté
    if not username:
        user = request.user
    else:
        user = get_object_or_404(User, username=username)
    
    # Récupérer le profil utilisateur
    try:
        profile = Profile.objects.get(user=user)
    except Profile.DoesNotExist:
        profile = None
    
    # Récupérer les informations supplémentaires de l'utilisateur
    try:
        user_key = UserKey.objects.get(user=user)
        public_key = user_key.public_key
    except UserKey.DoesNotExist:
        public_key = None
    
    # Récupérer les messages récents (les 3 derniers)
    recent_messages = Message.objects.filter(
        models.Q(sender=user) | models.Q(receiver=user)
    ).order_by('-timestamp')[:3]
    
    # Récupérer les messages chiffrés récents (les 3 derniers)
    recent_encrypted_messages = EncryptedMessage.objects.filter(
        models.Q(sender=user) | models.Q(receiver=user)
    ).order_by('-timestamp')[:3]
    
    # Combiner les activités récentes
    recent_activities = []
    
    # Ajouter les messages normaux
    for msg in recent_messages:
        if msg.sender == user:
            activity = {
                'action': f"Sent message to {msg.receiver.username}",
                'date': msg.timestamp,
                'type': 'message'
            }
        else:
            activity = {
                'action': f"Received message from {msg.sender.username}",
                'date': msg.timestamp,
                'type': 'message'
            }
        recent_activities.append(activity)
    
    # Ajouter les messages chiffrés
    for msg in recent_encrypted_messages:
        if msg.sender == user:
            activity = {
                'action': f"Sent encrypted message to {msg.receiver.username}",
                'date': msg.timestamp,
                'type': 'encrypted_message'
            }
        else:
            activity = {
                'action': f"Received encrypted message from {msg.sender.username}",
                'date': msg.timestamp,
                'type': 'encrypted_message'
            }
        recent_activities.append(activity)
    
    # Trier les activités par date (du plus récent au plus ancien)
    recent_activities.sort(key=lambda x: x['date'], reverse=True)
    # Ne garder que les 3 plus récentes
    recent_activities = recent_activities[:3]
    
    context = {
        'user_profile': user,
        'profile': profile,  # Ajout du profil
        'public_key': public_key,
        'recent_activities': recent_activities,
        'is_owner': request.user == user,  # Pour savoir si l'utilisateur voit son propre profil
    }
    
    return render(request, 'profil.html', context)



@login_required
@csrf_exempt  
def edit_profile_view(request):
    user = request.user
    try:
        profile = Profile.objects.get(user=user)
    except Profile.DoesNotExist:
        profile = Profile.objects.create(user=user)
    

    active_devices = UserDevice.objects.filter(user=user).order_by('-last_login')

    if request.method == 'POST':
        # Récupérer les données du formulaire
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        email = request.POST.get('email')
        phone_number = request.POST.get('phone_number')
        bio = request.POST.get('bio')
        profile_picture = request.FILES.get('profile_picture')
        remove_profile_picture = request.POST.get('remove_profile_picture') == 'on'

        # Valider les données
        errors = []
        if email and User.objects.filter(email=email).exclude(pk=user.pk).exists():
            errors.append("Cet email est déjà utilisé par un autre compte.")
        
        if errors:
            for error in errors:
                messages.error(request, error)
            return redirect('edit_profil')

        # Mettre à jour l'utilisateur
        update_fields = []
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            update_fields.append('first_name')
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            update_fields.append('last_name')
        if email and user.email != email:
            user.email = email
            update_fields.append('email')

        # Mettre à jour le profil
        profile_fields_updated = False
        if phone_number and profile.phone_number != phone_number:
            profile.phone_number = phone_number
            profile_fields_updated = True
        if bio and profile.bio != bio:
            profile.bio = bio
            profile_fields_updated = True
        
        # Gérer la photo de profil
        if remove_profile_picture and profile.profile_picture:
            profile.profile_picture.delete()
            profile.profile_picture = None
            profile_fields_updated = True
        elif profile_picture:
            # Supprimer l'ancienne photo si elle existe
            if profile.profile_picture:
                profile.profile_picture.delete()
            profile.profile_picture = profile_picture
            profile_fields_updated = True

        try:
            if update_fields:
                user.save(update_fields=update_fields)
            if profile_fields_updated:
                profile.save()
            
            messages.success(request, 'Profil mis à jour avec succès!')
            return redirect('profil')
        except Exception as e:
            messages.error(request, f'Une erreur est survenue: {str(e)}')
            return redirect('edit_profil')
    
    # Si la méthode n'est pas POST, afficher le formulaire
    context = {
        'user': user,
        'profile': profile,
        'devices': active_devices,  # Add this line

    }
    return render(request, 'edit-profile.html', context)
@login_required
def logout_device_view(request, session_key):
    """Déconnecte un appareil spécifique"""
    if request.method == 'POST':
        try:
            session = Session.objects.get(session_key=session_key)
            session_data = session.get_decoded()
            if session_data.get('_auth_user_id') == str(request.user.id):
                session.delete()
                return JsonResponse({'status': 'success'})
        except Session.DoesNotExist:
            pass
    return JsonResponse({'status': 'error'}, status=400)

@login_required
def logout_all_devices_view(request):
    """Déconnecte tous les appareils sauf l'appareil actuel"""
    if request.method == 'POST':
        current_session_key = request.session.session_key
        sessions = Session.objects.filter(expire_date__gte=timezone.now())
        
        count = 0
        for session in sessions:
            session_data = session.get_decoded()
            if (session_data.get('_auth_user_id') == str(request.user.id) 
                and session.session_key != current_session_key):
                session.delete()
                count += 1
        
        return JsonResponse({
            'status': 'success',
            'devices_logged_out': count
        })
    return JsonResponse({'status': 'error'}, status=400)

def get_active_sessions(user):
    """Récupère les sessions actives pour un utilisateur"""
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
    active_sessions = []
    
    for session in sessions:
        session_data = session.get_decoded()
        if session_data.get('_auth_user_id') == str(user.id):
            active_sessions.append({
                'session_key': session.session_key,
                'ip': session_data.get('ip', 'Unknown'),
                'user_agent': session_data.get('user_agent', 'Unknown'),
                'last_activity': session.expire_date - timezone.timedelta(
                    seconds=settings.SESSION_COOKIE_AGE)
            })
    
    return active_sessions

def search_users(request):
    if request.method == 'GET' and 'term' in request.GET:
        search_term = request.GET.get('term')
        users = User.objects.filter(
            Q(username__icontains=search_term) |
            Q(first_name__icontains=search_term) |
            Q(last_name__icontains=search_term),
            is_superuser=False  # This excludes superusers

        ).distinct()[:10]  # Limit to 10 results
        
        results = []
        for user in users:
            user_dict = {
                'id': user.id,
                'username': user.username,
                'full_name': f"{user.first_name} {user.last_name}".strip(),
                'profile_picture': user.profile.profile_picture.url if hasattr(user, 'profile') and user.profile.profile_picture else 'https://bootdey.com/img/Content/avatar/avatar7.png'
            }
            results.append(user_dict)
        
        return JsonResponse(results, safe=False)
    return JsonResponse({'error': 'Invalid request'}, status=400)


@login_required
def call_view(request):
    users = User.objects.exclude(id=request.user.id)
    return render(request, 'call.html', {'users': users})