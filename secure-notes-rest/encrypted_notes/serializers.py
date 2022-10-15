import os

from rest_framework import serializers
from django.db import transaction

from encrypted_notes.models import EncryptedNote, NoteAccessKey
from .encryption_utils import generate_password_key, encrypt_data, decrypt_data, binary_to_string, str_to_binary


class EncryptedNoteDefaultSerializer(serializers.ModelSerializer):
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = EncryptedNote
        fields = ['id', 'title', 'created', 'last_update', 'creator']


class EncryptedNoteCreationSerializer(serializers.ModelSerializer):
    DEFAULT_ACCESS_KEY_NAME = 'Initial'

    password = serializers.CharField(min_length=8, max_length=50, required=True, write_only=True)
    payload = serializers.CharField(required=True, write_only=True)
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = EncryptedNote
        exclude = ('content',)

    def create(self, validated_data):
        password = validated_data.pop('password')
        payload = validated_data.pop('payload')

        # Encrypt payload
        encrypted_payload, payload_encryption_key = encrypt_data(str_to_binary(payload))
        validated_data['content'] = encrypted_payload
        # Encrypt payload key with password
        password_salt = os.urandom(16)
        password_encryption_key = generate_password_key(password, password_salt)
        encrypted_key, *_ = encrypt_data(payload_encryption_key, key=password_encryption_key)

        with transaction.atomic():
            note = EncryptedNote.objects.create(**validated_data)
            NoteAccessKey.objects.create(note=note, name=self.DEFAULT_ACCESS_KEY_NAME, salt=password_salt,
                                         encrypted_key=encrypted_key)

        return note


class DecryptedNoteReadSerializer(EncryptedNoteDefaultSerializer):
    def to_representation(self, instance: EncryptedNote):
        if 'password' not in self.context:
            raise serializers.ValidationError("Must provide password to decrypt note!")
        password = self.context['password']

        ret = super().to_representation(instance)
        for note_access_key in instance.access_keys.all():
            try:
                # The BinaryFields are returned as a memoryview objects, hence the explicit conversion.
                salt = bytes(note_access_key.salt)
                binary_content = bytes(instance.content)
                binary_encrypted_key = bytes(note_access_key.encrypted_key)

                password_encryption_key = generate_password_key(password, salt)
                payload_encryption_key = decrypt_data(binary_encrypted_key, password_encryption_key)
                decrypted_payload = decrypt_data(binary_content, payload_encryption_key)
                ret['payload'] = decrypted_payload
                return ret
            except Exception as e:
                continue

        raise serializers.ValidationError("Provided password doesn't match any of the keys for this note!")

