from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from django.contrib.auth import authenticate, login, logout


# Create your views here.

class RegistrationView(View):

    def get(self, request):
        return render(request, 'accounts/register.html')

    def post(self, request):
        data = request.POST
        context = {
            'data': data,
            'has_error': False
        }
        email = request.POST.get('email')
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm-password')
        if len(password) < 6:
            messages.add_message(request, messages.ERROR, "Password should be at least 6 characters long!")
            context['has_error'] = True
        if password != confirm_password:
            messages.add_message(request, messages.ERROR, "Password don't match!")
            context['has_error'] = True
        if not validate_email(email):
            messages.add_message(request, messages.ERROR, "Please provide a valide email!")
            context['has_error'] = True

        if User.objects.filter(email=email).exists():
            messages.add_message(request, messages.ERROR, "Email is already taken")
            context['has_error'] = True

        if User.objects.filter(username=username).exists():
            messages.add_message(request, messages.ERROR, "Username is already taken")
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'accounts/register.html', context, status=400)
        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = firstname
        user.last_name = lastname
        user.is_active = False
        user.save()

        current_site = get_current_site(request)
        email_subject = "Active your Account"
        message = render_to_string(
            'accounts/emails/activate.html',
            {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': generate_token.make_token(user)
            }
        )
        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
        )
        email_message.send()

        messages.add_message(request, messages.SUCCESS, "Account created successfully.")
        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'accounts/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == '':
            messages.add_message(request, messages.ERROR, 'Username is required!')
            context['has_error'] = True
        if password == '':
            messages.add_message(request, messages.ERROR, 'Password is required!')
            context['has_error'] = True
        user = authenticate(request, username=username, password=password)

        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR, 'Invalid login credentials!')
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'accounts/login.html', status=401, context=context)
        login(request, user)
        return redirect('home')


class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Logout successfully.')
        return redirect('login')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        # Activate the user by setting the is_active status to True
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS, 'Congratulation! Your account is activated.')
            return redirect('login')
        return render(request, 'accounts/emails/activation_failed.html', status=401)


class HomeView(View):
    def get(self, request):
        return render(request, 'index.html')
