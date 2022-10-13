from rest_framework import generics
from rest_framework import permissions

from encrypted_notes.models import EncryptedNote
from encrypted_notes.serializers import EncryptedNoteDefaultSerializer, EncryptedNoteCreationSerializer


class EncryptedNoteList(generics.ListCreateAPIView):
    queryset = EncryptedNote.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return EncryptedNoteCreationSerializer
        else:
            return EncryptedNoteDefaultSerializer

    def perform_create(self, serializer):
        serializer.save(creator=self.request.user)
