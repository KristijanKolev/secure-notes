from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from rest_framework.response import Response

from encrypted_notes.models import EncryptedNote, NoteAccessKey
from encrypted_notes.serializers import (EncryptedNoteDefaultSerializer, EncryptedNoteCreationSerializer,
                                         DecryptedNoteReadSerializer, NoteAccessKeyCreationSerializer)


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


class DecryptedNoteDetail(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uuid):
        note = get_object_or_404(EncryptedNote, uuid=uuid)
        serializer = DecryptedNoteReadSerializer(note, context=request.data)
        return Response(serializer.data)


class NoteAccessKeyList(generics.ListCreateAPIView):
    serializer_class = NoteAccessKeyCreationSerializer

    def check_permissions(self, request):
        note = get_object_or_404(EncryptedNote, uuid=self.kwargs['note_uuid'])
        if request.user.is_anonymous:
            raise PermissionDenied("Must be authenticated to access this resource!")
        if request.user != note.creator:
            raise PermissionDenied("Must be note creator to access this resource!")

    def get_queryset(self):
        return NoteAccessKey.objects.filter(note__uuid=self.kwargs['note_uuid'])

    def perform_create(self, serializer):
        note = get_object_or_404(EncryptedNote, uuid=self.kwargs['note_uuid'])
        return serializer.save(note=note)
