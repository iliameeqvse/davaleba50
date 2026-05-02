from django.urls import path

from .views import (
    PasswordResetConfirmView,
    PasswordResetOTPConfirmView,
    PasswordResetOTPRequestView,
    PasswordResetRequestView,
)

urlpatterns = [
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),
    path('password-reset-otp/', PasswordResetOTPRequestView.as_view(), name='password-reset-otp'),
    path('password-reset-otp-confirm/', PasswordResetOTPConfirmView.as_view(), name='password-reset-otp-confirm'),
]
