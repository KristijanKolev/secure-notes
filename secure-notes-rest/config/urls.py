"""config URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from config.views import error400, error404, error500

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

handler400 = error400
handler404 = error404
handler500 = error500

urlpatterns = [
    path('api/admin/', admin.site.urls),
    path('api/', include('encrypted_notes.urls'), name='encrypted-notes'),
    path('api/auth/', include('user_management.urls'), name='user-management'),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
