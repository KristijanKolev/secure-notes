from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import InvalidToken
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.models import User
from django.db import IntegrityError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


REFRESH_TOKEN_COOKIE_NAME = 'refresh_token'


class CookieTokenRefreshSerializer(TokenRefreshSerializer):
    refresh = serializers.CharField(required=False)

    def validate(self, attrs):
        # If refresh token is not provided in the body check for 'refresh_token' cookie.
        if not attrs.get('refresh'):
            attrs['refresh'] = self.context['request'].COOKIES.get(REFRESH_TOKEN_COOKIE_NAME)

        if not attrs['refresh']:
            raise InvalidToken(f'No valid refresh token found in request body or cookie '
                               f'\'{REFRESH_TOKEN_COOKIE_NAME}\'')

        return super().validate(attrs)


class UserSignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, validators=[UnicodeUsernameValidator])
    password = serializers.CharField(max_length=128, write_only=True)

    def create(self, validated_data):
        try:
            new_user = User(username=validated_data['username'])
            new_user.set_password(validated_data['password'])
            new_user.save()
        except IntegrityError:
            raise serializers.ValidationError('Username already exists!')

        return {"username": new_user.username}


class UserDetailsTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username

        return token

