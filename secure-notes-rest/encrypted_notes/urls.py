from django.urls import path, include

from encrypted_notes import views


urlpatterns = [
    path('notes/', views.EncryptedNoteList.as_view(), name='notes-list'),
    path('notes/<int:pk>/decrypted', views.DecryptedNoteDetail.as_view(), name='note-decrypted')
]
