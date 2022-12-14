# Generated by Django 4.1.2 on 2022-10-19 13:39

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('encrypted_notes', '0004_encryptednote_populate_uuid_noteaccesskey_populate_uuid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='encryptednote',
            name='uuid',
            field=models.UUIDField(default=uuid.uuid4, unique=True),
        ),
        migrations.AlterField(
            model_name='noteaccesskey',
            name='uuid',
            field=models.UUIDField(default=uuid.uuid4, unique=True),
        ),
    ]
