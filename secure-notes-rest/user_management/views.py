from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView

from config.settings import SIMPLE_JWT
from user_management.serializers import CookieTokenRefreshSerializer, REFRESH_TOKEN_COOKIE_NAME


def add_refreshtoken_cookie(response):
    if response.data.get('refresh'):
        cookie_max_age = SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()
        response.set_cookie(REFRESH_TOKEN_COOKIE_NAME, response.data['refresh'], max_age=cookie_max_age, httponly=True)


class CookieTokenObtainPairView(TokenObtainPairView):
    def finalize_response(self, request, response, *args, **kwargs):
        add_refreshtoken_cookie(response)
        return super().finalize_response(request, response, *args, **kwargs)


class CookieTokenRefreshView(TokenRefreshView):
    def finalize_response(self, request, response, *args, **kwargs):
        add_refreshtoken_cookie(response)
        return super().finalize_response(request, response, *args, **kwargs)
    serializer_class = CookieTokenRefreshSerializer
