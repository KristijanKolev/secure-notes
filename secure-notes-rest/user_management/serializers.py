from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import InvalidToken


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
