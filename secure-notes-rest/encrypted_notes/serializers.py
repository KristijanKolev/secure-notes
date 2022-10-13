import os
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from rest_framework import serializers
from django.db import transaction

from encrypted_notes.models import EncryptedNote, NoteAccessKey


DEFAULT_PBKDF2HMAC_ITERATIONS = 480_000
DEFAULT_PBKDF2HMAC_LENGTH = 32


class EncryptedNoteDefaultSerializer(serializers.ModelSerializer):
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = EncryptedNote
        fields = ['id', 'title', 'created', 'last_update', 'creator']


class EncryptedNoteCreationSerializer(serializers.ModelSerializer):
    DEFAULT_ACCESS_KEY_NAME = 'Initial'

    password = serializers.CharField(max_length=50, required=True, write_only=True)
    payload = serializers.CharField(required=True, write_only=True)
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = EncryptedNote
        exclude = ('content',)

    def create(self, validated_data):
        password_binary = validated_data.pop('password').encode('utf-8')
        payload_binary = validated_data.pop('payload').encode('utf-8')

        # Encrypt payload

        payload_encryption_key = Fernet.generate_key()
        # Main encryptor used for encrypting the note payload with a random key
        payload_encryptor = Fernet(payload_encryption_key)
        encrypted_payload = payload_encryptor.encrypt(payload_binary)
        validated_data['content'] = encrypted_payload

        # Encrypt payload key with password

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=DEFAULT_PBKDF2HMAC_LENGTH,
            salt=salt,
            iterations=DEFAULT_PBKDF2HMAC_ITERATIONS,
        )
        password_encryption_key = base64.urlsafe_b64encode(kdf.derive(password_binary))
        # Encryptor used for encrypting the main encryption key using a user-defined password
        key_encryptor = Fernet(password_encryption_key)
        encrypted_key = key_encryptor.encrypt(payload_encryption_key)

        with transaction.atomic():
            note = EncryptedNote.objects.create(**validated_data)
            NoteAccessKey.objects.create(note=note, name=self.DEFAULT_ACCESS_KEY_NAME, salt=salt,
                                         encrypted_key=encrypted_key)

        return note

