from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView

from user_management import views

app_name = 'user-management'

urlpatterns = [
    path('token/', views.CookieTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', views.CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('signup/', views.UserSignupView.as_view(), name='signup'),
    path('logout/', views.logout, name='logout')
]
