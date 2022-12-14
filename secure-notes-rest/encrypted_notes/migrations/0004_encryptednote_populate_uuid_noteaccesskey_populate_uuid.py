# Generated by Django 4.1.2 on 2022-10-19 13:39

from django.db import migrations, models
import uuid


def gen_uuid(apps, schema_editor):
    EncryptedNote = apps.get_model('encrypted_notes', 'EncryptedNote')
    NoteAccessKey = apps.get_model('encrypted_notes', 'NoteAccessKey')

    for existing_note in EncryptedNote.objects.all():
        existing_note.uuid = uuid.uuid4()
        existing_note.save(update_fields=['uuid'])

    for existing_key in NoteAccessKey.objects.all():
        existing_key.uuid = uuid.uuid4()
        existing_key.save(update_fields=['uuid'])


class Migration(migrations.Migration):

    dependencies = [
        ('encrypted_notes', '0003_encryptednote_uuid_noteaccesskey_uuid'),
    ]

    operations = [
        migrations.RunPython(gen_uuid, reverse_code=migrations.RunPython.noop),
    ]
