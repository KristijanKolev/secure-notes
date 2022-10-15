from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework import permissions
from rest_framework.views import APIView
from rest_framework.response import Response

from encrypted_notes.models import EncryptedNote
from encrypted_notes.serializers import (EncryptedNoteDefaultSerializer, EncryptedNoteCreationSerializer,
                                         DecryptedNoteReadSerializer)


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

    def post(self, request, pk):
        note = get_object_or_404(EncryptedNote, pk=pk)
        serializer = DecryptedNoteReadSerializer(note, context=request.data)
        return Response(serializer.data)
