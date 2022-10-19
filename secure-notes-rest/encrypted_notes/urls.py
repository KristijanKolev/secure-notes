from django.urls import path, include

from encrypted_notes import views

app_name = 'encrypted-notes'

urlpatterns = [
    path('notes/', views.EncryptedNoteList.as_view(), name='notes-list'),
    path('notes/<uuid:uuid>/decrypted', views.DecryptedNoteDetail.as_view(), name='note-decrypted'),
    path('notes/<uuid:note_uuid>/keys', views.NoteAccessKeyList.as_view(), name='note-access-keys-list')
]
