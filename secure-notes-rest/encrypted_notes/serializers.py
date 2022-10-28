import io
import os

from rest_framework import serializers
from django.db import transaction
from django.db.utils import IntegrityError
from django.core.files.uploadedfile import InMemoryUploadedFile
from cryptography.fernet import InvalidToken

from encrypted_notes.models import EncryptedNote, NoteAccessKey, EncryptedNoteFile
from encrypted_notes.encryption_utils import (generate_password_key, encrypt_data, decrypt_data, binary_to_string,
                                              str_to_binary)


class EncryptedNoteDefaultSerializer(serializers.ModelSerializer):
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = EncryptedNote
        fields = ('uuid', 'title', 'created', 'last_update', 'creator')


class EncryptedNoteCreationSerializer(serializers.ModelSerializer):
    DEFAULT_ACCESS_KEY_NAME = 'Initial'

    password = serializers.CharField(min_length=8, max_length=50, required=True, write_only=True)
    payload = serializers.CharField(required=True, write_only=True)
    creator = serializers.ReadOnlyField(source='creator.username')

    class Meta:
        model = EncryptedNote
        exclude = ('content', 'id')

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


class NoteAccessKeyCreationSerializer(serializers.ModelSerializer):
    existing_password = serializers.CharField(min_length=8, max_length=50, required=True, write_only=True)
    new_password = serializers.CharField(min_length=8, max_length=50, required=True, write_only=True)

    class Meta:
        model = NoteAccessKey
        fields = ('uuid', 'name', 'created', 'existing_password', 'new_password')

    def create(self, validated_data):
        note = validated_data['note']
        existing_password = validated_data['existing_password']
        new_password = validated_data['new_password']
        new_salt = os.urandom(16)

        for existing_access_key in note.access_keys.all():
            salt = bytes(existing_access_key.salt)
            binary_encrypted_key = bytes(existing_access_key.encrypted_key)

            password_encryption_key = generate_password_key(existing_password, salt)
            try:
                payload_encryption_key = decrypt_data(binary_encrypted_key, password_encryption_key)
            except InvalidToken:
                # An InvalidToken exception means the password doesn't match the given access key.
                # Continuing cycle to try with the next key
                continue

            new_password_encryption_key = generate_password_key(new_password, new_salt)
            new_binary_encrypted_key, *_ = encrypt_data(payload_encryption_key, new_password_encryption_key)

            try:
                return NoteAccessKey.objects.create(
                    note=note,
                    name=validated_data['name'],
                    salt=new_salt,
                    encrypted_key=new_binary_encrypted_key
                )
            except IntegrityError as e:
                if 'unique constraint' in str(e).lower():
                    raise serializers.ValidationError("Name must be unique!")
                else:
                    raise e

        raise serializers.ValidationError("Provided password doesn't match any of the keys for this note!")


class EncryptedNoteFileSerializer(serializers.ModelSerializer):
    note = serializers.ReadOnlyField(source='note.name')
    name = serializers.CharField(max_length=200, read_only=True)
    password = serializers.CharField(min_length=8, max_length=50, required=True, write_only=True)
    file = serializers.FileField(write_only=True)

    class Meta:
        model = EncryptedNoteFile
        fields = ('uuid', 'created', 'file', 'name', 'note', 'password')

    def create(self, validated_data):
        password = validated_data['password']
        note = validated_data['note']
        original_file: InMemoryUploadedFile = validated_data['file']

        for existing_access_key in note.access_keys.all():
            salt = bytes(existing_access_key.salt)
            binary_encrypted_key = bytes(existing_access_key.encrypted_key)
            password_encryption_key = generate_password_key(password, salt)
            try:
                payload_encryption_key = decrypt_data(binary_encrypted_key, password_encryption_key)
            except InvalidToken:
                # An InvalidToken exception means the password doesn't match the given access key.
                # Continuing cycle to try with the next key
                continue

            file_contents = original_file.read()
            encrypted_contents, *_ = encrypt_data(file_contents, payload_encryption_key)
            encrypted_buffer = io.BytesIO(encrypted_contents)
            encrypted_file = InMemoryUploadedFile(
                encrypted_buffer,
                field_name=original_file.field_name,
                name=original_file.name,
                content_type=original_file.content_type,
                size=original_file.size,
                charset=original_file.charset
            )

            try:
                return EncryptedNoteFile.objects.create(
                    note=note,
                    file=encrypted_file,
                    name=original_file.name
                )
            except IntegrityError as e:
                if 'unique constraint' in str(e).lower():
                    raise serializers.ValidationError("Filename must be unique for this note!")
                else:
                    raise e

        raise serializers.ValidationError("Provided password doesn't match any of the keys for file!")


def decrypt_file(encrypted_file: EncryptedNoteFile, password: str):
    for note_access_key in encrypted_file.note.access_keys.all():
        salt = bytes(note_access_key.salt)
        binary_content = bytes(encrypted_file.file.read())
        binary_encrypted_key = bytes(note_access_key.encrypted_key)

        password_encryption_key = generate_password_key(password, salt)
        try:
            payload_encryption_key = decrypt_data(binary_encrypted_key, password_encryption_key)
        except InvalidToken:
            # An InvalidToken exception means the password doesn't match the given access key.
            # Continuing cycle to try with the next key
            continue
        return decrypt_data(binary_content, payload_encryption_key)

    raise serializers.ValidationError("Provided password doesn't match any of the keys for this file!")


class DecryptedNoteReadSerializer(EncryptedNoteDefaultSerializer):
    attachments = EncryptedNoteFileSerializer(many=True)

    class Meta(EncryptedNoteDefaultSerializer.Meta):
        fields = EncryptedNoteDefaultSerializer.Meta.fields + ('attachments', )

    def to_representation(self, instance: EncryptedNote):
        if 'password' not in self.context:
            raise serializers.ValidationError("Must provide password to decrypt note!")
        password = self.context['password']

        ret = super().to_representation(instance)
        for note_access_key in instance.access_keys.all():
            # The BinaryFields are returned as a memoryview objects, hence the explicit conversion.
            salt = bytes(note_access_key.salt)
            binary_content = bytes(instance.content)
            binary_encrypted_key = bytes(note_access_key.encrypted_key)

            password_encryption_key = generate_password_key(password, salt)
            try:
                payload_encryption_key = decrypt_data(binary_encrypted_key, password_encryption_key)
            except InvalidToken:
                # An InvalidToken exception means the password doesn't match the given access key.
                # Continuing cycle to try with the next key
                continue
            decrypted_payload = decrypt_data(binary_content, payload_encryption_key)
            ret['payload'] = binary_to_string(decrypted_payload)
            return ret

        raise serializers.ValidationError("Provided password doesn't match any of the keys for this note!")
