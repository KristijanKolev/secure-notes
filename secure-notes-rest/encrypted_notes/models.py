import uuid

from django.db import models


class EncryptedNote(models.Model):
    uuid = models.UUIDField(unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    creator = models.ForeignKey('auth.User', related_name='snippets', on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    content = models.BinaryField(editable=True, blank=True)

    class Meta:
        ordering = ['-created']

    def __str__(self):
        return f'EncryptedNote({self.uuid}): {self.title}'


class NoteAccessKey(models.Model):
    uuid = models.UUIDField(unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)
    note = models.ForeignKey(EncryptedNote, related_name='access_keys', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    salt = models.BinaryField(max_length=16)
    encrypted_key = models.BinaryField()

    class Meta:
        unique_together = ('note', 'name')
        ordering = ['-created']

    def __str__(self):
        return f'NoteAccessKey({self.uuid}): {self.note.title} | {self.name}'


class EncryptedNoteFile(models.Model):

    def _generate_file_path(self, original_name):
        return f'note_files/{self.note.uuid}/{original_name}'

    uuid = models.UUIDField(unique=True, default=uuid.uuid4)
    created = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to=_generate_file_path)
    note = models.ForeignKey(EncryptedNote, related_name='attachments', on_delete=models.CASCADE)
    name = models.CharField(max_length=200)

    class Meta:
        unique_together = ('note', 'name')
        ordering = ['-created']
