# Generated by Django 5.0.2 on 2024-05-13 12:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('galv', '0025_rename_uuid_arbitraryfile_id_rename_uuid_cell_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='observedfile',
            name='png',
            field=models.ImageField(blank=True, help_text='Preview image of the file', null=True, upload_to=''),
        ),
    ]
