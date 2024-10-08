# Generated by Django 5.0.2 on 2024-04-05 11:51

import galv.storages
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("galv", "0007_alter_datacolumn_type"),
    ]

    operations = [
        migrations.AlterField(
            model_name="presigneddatafile",
            name="file",
            field=models.FileField(
                blank=True,
                null=True,
                storage=galv.storages.LocalDataStorage,
                upload_to="",
            ),
        ),
    ]
