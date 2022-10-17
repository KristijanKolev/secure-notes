from django.db import models


class EncryptedNote(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)
    creator = models.ForeignKey('auth.User', related_name='snippets', on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    content = models.BinaryField(editable=True, blank=True)

    def __str__(self):
        return f'EncryptedNote({self.id}): {self.title}'


class NoteAccessKey(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    note = models.ForeignKey(EncryptedNote, related_name='access_keys', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    salt = models.BinaryField(max_length=16)
    encrypted_key = models.BinaryField()

    class Meta:
        unique_together = ('note', 'name')

    def __str__(self):
        return f'NoteAccessKey({self.id}): {self.note.title} | {self.name}'
