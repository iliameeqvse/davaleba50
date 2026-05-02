from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import PasswordResetOTP
from .serializers import (
    PasswordResetConfirmSerializer,
    PasswordResetOTPConfirmSerializer,
    PasswordResetOTPRequestSerializer,
    PasswordResetRequestSerializer,
)
from .utils import generate_otp_code

User = get_user_model()
GENERIC_MESSAGE = 'If the account exists, reset instructions have been sent.'


class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if user:
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            reset_link = settings.FRONTEND_RESET_URL.format(uid=uid, token=token)
            send_mail('Password reset request', f'Use this link to reset your password: {reset_link}', settings.DEFAULT_FROM_EMAIL, [email])

        return Response({'detail': GENERIC_MESSAGE}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data['uid']))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({'detail': 'Invalid reset credentials.'}, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data['token']
        if not default_token_generator.check_token(user, token):
            return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save(update_fields=['password'])
        return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)


class PasswordResetOTPRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetOTPRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(email__iexact=email).first()
        if user:
            code = generate_otp_code()
            expires_at = timezone.now() + timedelta(minutes=getattr(settings, 'OTP_EXPIRY_MINUTES', 10))
            PasswordResetOTP.objects.filter(user=user, is_used=False).update(is_used=True)
            PasswordResetOTP.objects.create(user=user, code=code, expires_at=expires_at)
            send_mail('Password reset OTP', f'Your password reset code is: {code}', settings.DEFAULT_FROM_EMAIL, [email])

        return Response({'detail': GENERIC_MESSAGE}, status=status.HTTP_200_OK)


class PasswordResetOTPConfirmView(APIView):
    @transaction.atomic
    def post(self, request):
        serializer = PasswordResetOTPConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.filter(email__iexact=serializer.validated_data['email']).first()
        if not user:
            return Response({'detail': 'Invalid code or email.'}, status=status.HTTP_400_BAD_REQUEST)

        otp = PasswordResetOTP.objects.filter(
            user=user,
            code=serializer.validated_data['code'],
            is_used=False,
        ).order_by('-created_at').first()

        if not otp or otp.is_expired:
            return Response({'detail': 'Invalid or expired OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save(update_fields=['password'])
        otp.is_used = True
        otp.save(update_fields=['is_used'])

        return Response({'detail': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
