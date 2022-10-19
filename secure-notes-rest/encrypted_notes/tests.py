import os
import uuid

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase, URLPatternsTestCase
from rest_framework import status

from .models import EncryptedNote, NoteAccessKey
from .encryption_utils import (generate_password_key, generate_random_key, encrypt_data, decrypt_data, binary_to_string,
                               str_to_binary)


class EncryptionUtilsTests(APITestCase):
    def test_password_key_generation(self):
        password = 'my p4ssw0rd'
        salt = b'\xbe\xd1\r\xee?\xef(\r\xcb\xe6>\xc9\xcb\\Q\x07'
        password_key = generate_password_key(password, salt)

        self.assertEqual(password_key, b'Ytqyn5wdllS0nc0Gi0D3szB3gA_nUGyk0hl3Dtf8f0o=')

    def test_random_key_encryption(self):
        key = generate_random_key()
        data = b'Test data string'
        encrypted, *_ = encrypt_data(data, key)
        decrypted = decrypt_data(encrypted, key)

        self.assertEqual(data, decrypted)

    def test_password_encryption(self):
        password = 'my p4assw0rd'
        salt = b'|}\xef\xb3~x\x82\xb7\x8b\x81\x90\n\xc3dz\x15'
        data = b'Test data string'

        password_encryption_key = generate_password_key(password, salt)
        encrypted, *_ = encrypt_data(data, password_encryption_key)

        # re-generating the key to mimic real-life scenario and ensure there's no randomness in the key generation.
        password_decryption_key = generate_password_key(password, salt)
        decrypted = decrypt_data(encrypted, password_decryption_key)

        self.assertEqual(data, decrypted)


class NoteViewsTests(APITestCase):

    @staticmethod
    def _create_user(username, password):
        user = get_user_model().objects.create(username=username)
        user.set_password(password)
        user.save()
        return user

    @staticmethod
    def _create_note(title, payload, note_password, creator):
        encrypted_payload, payload_encryption_key = encrypt_data(str_to_binary(payload))
        # Encrypt payload key with password
        password_salt = os.urandom(16)
        password_encryption_key = generate_password_key(note_password, password_salt)
        encrypted_key, *_ = encrypt_data(payload_encryption_key, key=password_encryption_key)

        note = EncryptedNote.objects.create(title=title, content=encrypted_payload, creator=creator)
        NoteAccessKey.objects.create(note=note, name='Initial', salt=password_salt, encrypted_key=encrypted_key)

        return note

    def test_note_creation(self):
        user = self._create_user('login_user', '12345')
        self.client.login(username='login_user', password='12345')
        post_data = {
            "password": "note password",
            "payload": "Data to be encrypted",
            "title": "Test"
        }

        creation_response = self.client.post(reverse('encrypted-notes:notes-list'), data=post_data)
        self.assertEqual(creation_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(creation_response.data['creator'], user.username)
        self.assertEqual(creation_response.data['title'], 'Test')
        self.assertNotIn('payload', creation_response.data)

        note = EncryptedNote.objects.get(uuid=creation_response.data['uuid'])
        self.assertIsNotNone(note.content)
        self.assertIsInstance(note.content, memoryview)
        self.assertEqual(note.title, 'Test')
        self.assertEqual(note.creator, user)

    def test_decrypted_note_fetch(self):
        user = self._create_user('login_user', '12345')
        self.client.login(username='login_user', password='12345')
        note_title = 'Test'
        note_payload = 'Data to be encrypted'
        note_password = '123456'
        note = self._create_note(title=note_title, payload=note_payload, note_password=note_password, creator=user)

        response = self.client.post(reverse('encrypted-notes:note-decrypted', kwargs={'uuid': note.uuid}),
                                    data={'password': note_password})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], note_title)
        self.assertEqual(response.data['creator'], user.username)
        self.assertEqual(response.data['payload'], note_payload)

    def test_decrypted_not_found(self):
        self._create_user('login_user', '12345')
        self.client.login(username='login_user', password='12345')
        response = self.client.post(reverse('encrypted-notes:note-decrypted', kwargs={'uuid': uuid.uuid4()}),
                                    data={'password': ''})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_decrypted_wrong_password(self):
        user = self._create_user('login_user', '12345')
        self.client.login(username='login_user', password='12345')
        note_title = 'Test'
        note_payload = 'Data to be encrypted'
        note_password = '123456'
        note = self._create_note(title=note_title, payload=note_payload, note_password=note_password, creator=user)

        response = self.client.post(reverse('encrypted-notes:note-decrypted', kwargs={'uuid': note.uuid}),
                                    data={'password': 'incorrect'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
