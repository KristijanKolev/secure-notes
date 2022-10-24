import os
import uuid

from cryptography.fernet import InvalidToken
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
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


class ViewsTests(APITestCase):

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

    @staticmethod
    def _add_access_key(note, existing_password, name, password):
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

            new_salt = os.urandom(16)
            new_password_encryption_key = generate_password_key(password, new_salt)
            new_binary_encrypted_key, *_ = encrypt_data(payload_encryption_key, new_password_encryption_key)

            return NoteAccessKey.objects.create(
                note=note,
                name=name,
                salt=new_salt,
                encrypted_key=new_binary_encrypted_key
            )

    def test_note_creation(self):
        user = self._create_user('login_user', '12345')
        self.client.force_authenticate(user=user)
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

    def test_note_list_filter(self):
        """
        Creating two notes with different creators. Only the first should be displayed in the list view.
        """
        user1 = self._create_user('login_user', '12345')
        user2 = self._create_user('user2', '12345')

        self.client.force_authenticate(user=user1)

        note1 = self._create_note(title='Note1', payload='Test payload', note_password='12345', creator=user1)
        self._create_note(title='Note2', payload='Empty', note_password='12345', creator=user2)

        response = self.client.get(reverse('encrypted-notes:notes-list'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['uuid'], str(note1.uuid))

    def test_note_key_list(self):
        user = self._create_user('login_user', '12345')
        self.client.force_authenticate(user=user)
        note = self._create_note(title='Note1', payload='Test payload', note_password='12345', creator=user)
        self._add_access_key(note, '12345', 'key-2', '12345')
        expected_uuids = {str(access_key.uuid) for access_key in note.access_keys.all()}

        response = self.client.get(reverse('encrypted-notes:note-access-keys-list', kwargs={'note_uuid': note.uuid}))
        results_uuids = {access_key['uuid'] for access_key in response.data['results']}
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(results_uuids, expected_uuids)

    def test_note_key_list_non_creator(self):
        user1 = self._create_user('user-1', '12345')
        user2 = self._create_user('user-2', '12345')
        self.client.force_authenticate(user=user1)
        note = self._create_note(title='Note1', payload='Test payload', note_password='12345', creator=user2)

        response = self.client.get(reverse('encrypted-notes:note-access-keys-list', kwargs={'note_uuid': note.uuid}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_note_key_create(self):
        user = self._create_user('user-1', '12345')
        self.client.force_authenticate(user=user)
        note = self._create_note(title='Note1', payload='Test payload', note_password='existing_pass', creator=user)

        response = self.client.post(reverse('encrypted-notes:note-access-keys-list', kwargs={'note_uuid': note.uuid}),
                                    data={
                                        "name": "key #2",
                                        "existing_password": "existing_pass",
                                        "new_password": "new_pass"
                                    })
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(note.access_keys.count(), 2)
        self.assertEqual(note.access_keys.filter(uuid=response.data['uuid']).count(), 1)

    def test_note_key_create_non_creator(self):
        user1 = self._create_user('user-1', '12345')
        user2 = self._create_user('user-2', '12345')
        self.client.force_authenticate(user=user1)
        note = self._create_note(title='Note1', payload='Test payload', note_password='existing_pass', creator=user2)
        initial_key_uuid = note.access_keys.all()[0].uuid

        response = self.client.post(reverse('encrypted-notes:note-access-keys-list', kwargs={'note_uuid': note.uuid}),
                                    data={
                                        "name": "key #2",
                                        "existing_password": "existing_pass",
                                        "new_password": "new_pass"
                                    })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(note.access_keys.count(), 1)
        self.assertEqual(note.access_keys.filter(uuid=initial_key_uuid).count(), 1)

    def test_note_key_delete(self):
        user = self._create_user('user-1', '12345')
        self.client.force_authenticate(user=user)
        note = self._create_note(title='Note1', payload='Test payload', note_password='12345', creator=user)
        initial_key_uuid = note.access_keys.all()[0].uuid
        second_key = self._add_access_key(note, '12345', 'key-2', '6789')

        response = self.client.delete(reverse('encrypted-notes:access-key-detail', kwargs={'uuid': second_key.uuid}))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(note.access_keys.count(), 1)
        self.assertEqual(note.access_keys.filter(uuid=initial_key_uuid).count(), 1)

    def test_note_key_delete_non_creator(self):
        user1 = self._create_user('user-1', 'pass 1')
        user2 = self._create_user('user-2', 'pass 2')
        self.client.force_authenticate(user=user2)
        note = self._create_note(title='Note1', payload='Test payload', note_password='12345', creator=user1)
        initial_key = note.access_keys.all()[0]
        second_key = self._add_access_key(note, '12345', 'key-2', '6789')

        response = self.client.delete(reverse('encrypted-notes:access-key-detail', kwargs={'uuid': second_key.uuid}))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(note.access_keys.count(), 2)
        self.assertEqual(note.access_keys.filter(uuid=initial_key.uuid).count(), 1)
        self.assertEqual(note.access_keys.filter(uuid=second_key.uuid).count(), 1)

    def test_added_key_decrypt(self):
        user = self._create_user('login_user', '12345')
        note_title = 'Test'
        note_payload = 'Data to be encrypted'
        initial_password = '123456'
        second_password = 'second password test'
        note = self._create_note(title=note_title, payload=note_payload, note_password=initial_password, creator=user)
        self._add_access_key(note, initial_password, 'key-2', second_password)
        response = self.client.post(reverse('encrypted-notes:note-decrypted', kwargs={'uuid': note.uuid}),
                                    data={'password': second_password})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], note_title)
        self.assertEqual(response.data['creator'], user.username)
        self.assertEqual(response.data['payload'], note_payload)
