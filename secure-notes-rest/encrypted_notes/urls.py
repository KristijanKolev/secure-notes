from django.urls import path, include

from encrypted_notes import views

app_name = 'encrypted-notes'

urlpatterns = [
    path('notes/', views.EncryptedNoteList.as_view(), name='notes-list'),
    path('notes/<uuid:uuid>/decrypted', views.DecryptedNoteDetail.as_view(), name='note-decrypted'),
    path('notes/<uuid:note_uuid>/keys', views.NoteAccessKeyList.as_view(), name='note-access-keys-list'),
    path('notes/<uuid:note_uuid>/attachments', views.EncryptedFileList.as_view(), name='note-files-list'),

    path('keys/<uuid:uuid>', views.NoteAccessKeyDetail.as_view(), name='access-key-detail'),



    path('docs/', views.DecryptedFileDownload.as_view())
]
