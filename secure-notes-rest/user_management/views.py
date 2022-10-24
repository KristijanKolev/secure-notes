from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView, TokenObtainPairView
from drf_spectacular.utils import extend_schema

from config.settings import SIMPLE_JWT
from user_management.serializers import REFRESH_TOKEN_COOKIE_NAME, CookieTokenRefreshSerializer, UserSignupSerializer


def add_refreshtoken_cookie(response):
    if response.data.get('refresh'):
        cookie_max_age = SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()
        response.set_cookie(REFRESH_TOKEN_COOKIE_NAME, response.data['refresh'], max_age=cookie_max_age, httponly=True)


class CookieTokenObtainPairView(TokenObtainPairView):
    def finalize_response(self, request, response, *args, **kwargs):
        add_refreshtoken_cookie(response)
        return super().finalize_response(request, response, *args, **kwargs)


class CookieTokenRefreshView(TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        add_refreshtoken_cookie(response)
        return super().finalize_response(request, response, *args, **kwargs)


@extend_schema(
    request=UserSignupSerializer,
    responses={201: UserSignupSerializer}
)
class UserSignupView(APIView):
    """
    Register a new user with the provided credentials.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save())
