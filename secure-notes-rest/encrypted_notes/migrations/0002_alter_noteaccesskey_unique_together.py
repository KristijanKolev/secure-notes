# Generated by Django 4.1.2 on 2022-10-17 07:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('encrypted_notes', '0001_initial'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='noteaccesskey',
            unique_together={('note', 'name')},
        ),
    ]
