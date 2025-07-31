"""
CyberAratta Authentication Views
Բարելավված authentication system հետ 2FA
"""
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone
from apps.core.security import security_rate_limit, sanitize_input, log_security_event
from .auth_models import CyberArattaUser, UserSession, SecurityLog
import pyotp
import qrcode
import io
import base64

@security_rate_limit(key='login', rate='5/m', method='POST')
@csrf_protect
def user_login(request):
    """Բարելավված մուտքի համակարգ"""
    if request.method == 'POST':
        username = sanitize_input(request.POST.get('username', ''))
        password = request.POST.get('password', '')
        totp_token = sanitize_input(request.POST.get('totp_token', ''))
        
        client_ip = request.META.get('REMOTE_ADDR', 'unknown')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            user = CyberArattaUser.objects.get(username=username)
            
            # Ստուգել արդյոք հաշիվը կողպված է
            if user.is_account_locked():
                log_security_event('LOGIN_BLOCKED_LOCKED_ACCOUNT', client_ip, f'User: {username}')
                messages.error(request, 'Ձեր հաշիվը ժամանակավորապես կողպված է: Խնդրում ենք փորձել ավելի ուշ:')
                return render(request, 'auth/login.html')
            
            # Authentication
            authenticated_user = authenticate(request, username=username, password=password)
            
            if authenticated_user:
                # 2FA ստուգում եթե միացված է
                if user.two_factor_enabled:
                    if not totp_token:
                        # Պահանջել 2FA token
                        request.session['pre_2fa_user_id'] = user.id
                        return render(request, 'auth/2fa_required.html', {'user': user})
                    
                    # TOTP token ստուգում
                    if not (user.verify_totp(totp_token) or user.verify_backup_token(totp_token)):
                        user.record_failed_login()
                        SecurityLog.objects.create(
                            user=user,
                            event_type='login_failed',
                            ip_address=client_ip,
                            user_agent=user_agent,
                            details={'reason': '2FA_FAILED'}
                        )
                        log_security_event('2FA_FAILED', client_ip, f'User: {username}')
                        messages.error(request, 'Անվավեր 2FA կոդ:')
                        return render(request, 'auth/2fa_required.html', {'user': user})
                
                # Հաջողված մուտք
                login(request, authenticated_user)
                user.record_successful_login(client_ip)
                
                # Session գրանցում
                UserSession.objects.create(
                    user=user,
                    session_key=request.session.session_key,
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                
                SecurityLog.objects.create(
                    user=user,
                    event_type='login_success',
                    ip_address=client_ip,
                    user_agent=user_agent
                )
                
                messages.success(request, 'Բարի գալուստ CyberAratta!')
                return redirect('core:dashboard')
            
            else:
                # Ձախողված մուտք
                user.record_failed_login()
                SecurityLog.objects.create(
                    user=user,
                    event_type='login_failed',
                    ip_address=client_ip,
                    user_agent=user_agent,
                    details={'reason': 'INVALID_CREDENTIALS'}
                )
                log_security_event('LOGIN_FAILED', client_ip, f'User: {username}')
                messages.error(request, 'Անվավեր մուտքային տվյալներ:')
        
        except CyberArattaUser.DoesNotExist:
            # Գրանցել անհայտ օգտատերի փորձ
            SecurityLog.objects.create(
                event_type='login_failed',
                ip_address=client_ip,
                user_agent=user_agent,
                details={'reason': 'USER_NOT_FOUND', 'attempted_username': username}
            )
            log_security_event('LOGIN_ATTEMPT_UNKNOWN_USER', client_ip, f'Username: {username}')
            messages.error(request, 'Անվավեր մուտքային տվյալներ:')
    
    return render(request, 'auth/login.html')

@login_required
def setup_2fa(request):
    """2FA կարգավորում"""
    user = request.user
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'enable':
            if not user.two_factor_enabled:
                secret = user.enable_two_factor()
                
                # QR կոդ ստեղծում
                totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                    name=user.username,
                    issuer_name="CyberAratta"
                )
                
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(totp_uri)
                qr.make(fit=True)
                
                img = qr.make_image(fill_color="black", back_color="white")
                buffer = io.BytesIO()
                img.save(buffer, format='PNG')
                qr_code_data = base64.b64encode(buffer.getvalue()).decode()
                
                SecurityLog.objects.create(
                    user=user,
                    event_type='2fa_enabled',
                    ip_address=request.META.get('REMOTE_ADDR', 'unknown'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                return render(request, 'auth/2fa_setup.html', {
                    'secret': secret,
                    'qr_code': qr_code_data,
                    'backup_tokens': user.backup_tokens
                })
        
        elif action == 'disable':
            user.disable_two_factor()
            SecurityLog.objects.create(
                user=user,
                event_type='2fa_disabled',
                ip_address=request.META.get('REMOTE_ADDR', 'unknown'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            messages.success(request, '2FA անջատվել է:')
    
    return render(request, 'auth/2fa_settings.html', {'user': user})

@login_required
def user_sessions(request):
    """Օգտատերի ակտիվ sessions-ների ցուցադրում"""
    sessions = UserSession.objects.filter(user=request.user, is_active=True)
    return render(request, 'auth/sessions.html', {'sessions': sessions})

@login_required
def revoke_session(request, session_id):
    """Session-ի հետկանչում"""
    try:
        session = UserSession.objects.get(id=session_id, user=request.user)
        session.is_active = False
        session.save()
        
        SecurityLog.objects.create(
            user=request.user,
            event_type='session_revoked',
            ip_address=request.META.get('REMOTE_ADDR', 'unknown'),
            details={'revoked_session_id': session_id}
        )
        
        messages.success(request, 'Session-ը հետկանչվել է:')
    except UserSession.DoesNotExist:
        messages.error(request, 'Session-ը գտնվել չի:')
    
    return redirect('auth:sessions')

def user_logout(request):
    """Բարելավված դուրս գալու համակարգ"""
    if request.user.is_authenticated:
        # Ապաակտիվացնել ընթացիկ session
        try:
            session = UserSession.objects.get(
                user=request.user,
                session_key=request.session.session_key,
                is_active=True
            )
            session.is_active = False
            session.save()
        except UserSession.DoesNotExist:
            pass
        
        SecurityLog.objects.create(
            user=request.user,
            event_type='logout',
            ip_address=request.META.get('REMOTE_ADDR', 'unknown'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
    
    logout(request)
    messages.success(request, 'Դուք դուրս եկաք համակարգից:')
    return redirect('core:home')
