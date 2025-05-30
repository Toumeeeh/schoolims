from dj_rest_auth.serializers import LoginSerializer as BaseLoginSerializer, UserDetailsSerializer as BaseUserDetailsSerializer
from django.contrib.auth import authenticate, get_user_model
from rest_framework import  exceptions
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from dj_rest_auth.registration.serializers import (
    RegisterSerializer as BaseRegisterSerializer,
)
User = get_user_model()

class RegisterSerializer(BaseRegisterSerializer):
    first_name = serializers.CharField(max_length=50, required=True)
    last_name = serializers.CharField(max_length=50, required=True)
    mobile = serializers.CharField(max_length=15, required=True)

    def save(self, request):
        user = super().save(request)
        user.first_name = self.validated_data.get("first_name", "")
        user.last_name = self.validated_data.get("last_name", "")
        user.mobile = self.validated_data.get("mobile", "")
        user.save()
        return user

class LoginSerializer(BaseLoginSerializer):
    credential = serializers.CharField(required=True)
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop("username", None)
        self.fields.pop("email", None)

    def authenticate(self, **kwargs):
        return authenticate(self.context["request"], **kwargs)\


    def validate(self, attrs):
        credential = attrs.get("credential")
        password = attrs.get("password")

        if not credential or not password:
            raise exceptions.ValidationError(_("Must include 'credential' and 'password'."))

        user = None
        if "@" in credential and "." in credential:
            try:
                user = User.objects.get(email__iexact=credential)
            except User.DoesNotExist:
                pass
        else:
            try:
                user = User.objects.get(mobile=credential)
            except User.DoesNotExist:
                pass

        if user:
            user = self.authenticate(username=user.username, password=password)

        if not user:
            raise exceptions.ValidationError(_("Invalid email/mobile or password."))

        attrs["user"] = user
        return attrs

class UserDetailsSerializer(BaseUserDetailsSerializer):
    class Meta:
        model = User
        fields = ("pk", "username", "email", "first_name", "last_name", "mobile")