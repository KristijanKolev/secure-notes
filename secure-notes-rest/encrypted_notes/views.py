import mimetypes

from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from django.conf import settings
from rest_framework import status, generics, permissions, serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser

from util.exceptions import CustomStatusError
from encrypted_notes.models import EncryptedNote, NoteAccessKey, EncryptedNoteFile
from encrypted_notes.serializers import (EncryptedNoteDefaultSerializer, DecryptedNoteReadSerializer,
                                         NoteAccessKeyCreationSerializer, EncryptedNoteFileSerializer, decrypt_file)
from encrypted_notes.pagination import DefaultPagination
from encrypted_notes.permissions import IsCreatorOrReadOnly


class EncryptedNoteList(generics.ListCreateAPIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = DefaultPagination
    serializer_class = EncryptedNoteDefaultSerializer

    def get_queryset(self):
        return EncryptedNote.objects.filter(creator=self.request.user)

    def perform_create(self, serializer):
        serializer.save(creator=self.request.user)


class DecryptedNoteDetail(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uuid):
        note = get_object_or_404(EncryptedNote, uuid=uuid)
        serializer = DecryptedNoteReadSerializer(note, context=request.data)
        return Response(serializer.data)


class NoteDelete(generics.DestroyAPIView):
    permission_classes = [IsCreatorOrReadOnly]
    queryset = EncryptedNote.objects.all()
    lookup_field = 'uuid'


class NoteChildPermissionsMixin:
    def check_permissions(self, request):
        note = get_object_or_404(EncryptedNote, uuid=self.kwargs['note_uuid'])
        if request.user.is_anonymous:
            raise PermissionDenied("Must be authenticated to access this resource!")
        if request.user != note.creator:
            raise PermissionDenied("Must be note creator to access this resource!")


class NoteAccessKeyList(NoteChildPermissionsMixin, generics.ListCreateAPIView):
    serializer_class = NoteAccessKeyCreationSerializer
    pagination_class = DefaultPagination

    def get_queryset(self):
        return NoteAccessKey.objects.filter(note__uuid=self.kwargs['note_uuid'])

    def perform_create(self, serializer):
        note = get_object_or_404(EncryptedNote, uuid=self.kwargs['note_uuid'])
        return serializer.save(note=note)


class NoteAccessKeyDetail(APIView):

    def delete(self, request, uuid):
        access_key = get_object_or_404(NoteAccessKey, uuid=uuid)

        if request.user != access_key.note.creator:
            raise PermissionDenied("Must be note creator to remove access key!")

        if access_key.note.access_keys.all().count() == 1:
            return Response(
                data={'detail': 'Cannot delete note\'s only access key. Add a new key before deleting this one.'},
                status=status.HTTP_409_CONFLICT
            )

        access_key.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class EncryptedFileList(NoteChildPermissionsMixin, generics.ListCreateAPIView):
    serializer_class = EncryptedNoteFileSerializer
    parser_classes = [MultiPartParser]

    def get_queryset(self):
        return EncryptedNoteFile.objects.filter(note__uuid=self.kwargs['note_uuid'])

    def perform_create(self, serializer):
        note = get_object_or_404(EncryptedNote, uuid=self.kwargs['note_uuid'])
        attachments_limit = settings.ENCRYPTED_NOTES['NOTE_MAX_ATTACHMENTS']
        if self.get_queryset().count() >= attachments_limit:
            raise CustomStatusError(
                status_code=status.HTTP_409_CONFLICT,
                detail=f'Limit of attachments exceeded for this note. Max allowed: {attachments_limit}.',
                code='limit_exceeded'
            )
        return serializer.save(note=note)


class DecryptedFileDetail(APIView):
    permission_classes = [permissions.AllowAny]

    def check_permissions(self, request):
        if request.method == 'DELETE':
            encrypted_file = get_object_or_404(EncryptedNoteFile, uuid=self.kwargs['uuid'])
            if request.user.is_anonymous:
                raise PermissionDenied("Must be authenticated to delete this resource!")
            if request.user != encrypted_file.note.creator:
                raise PermissionDenied("Must be parent note creator to delete this resource!")


    def post(self, request, uuid):
        encrypted_file = get_object_or_404(EncryptedNoteFile, uuid=uuid)
        if 'password' not in request.data:
            raise serializers.ValidationError("Must provide password to decrypt note!")
        password = request.data['password']
        decrypted_contents = decrypt_file(encrypted_file, password)

        mimetype, _ = mimetypes.guess_type(encrypted_file.name)
        response = HttpResponse(decrypted_contents, content_type=mimetype)
        response['Content-Disposition'] = f"attachment; filename={encrypted_file.name}"

        return response

    def delete(self, request, uuid):
        encrypted_file = get_object_or_404(EncryptedNoteFile, uuid=uuid)
        encrypted_file.delete()

        return Response(status=status.HTTP_204_NO_CONTENT)
