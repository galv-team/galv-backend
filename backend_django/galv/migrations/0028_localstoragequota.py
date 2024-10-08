# Generated by Django 5.0.3 on 2024-05-21 15:25

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("galv", "0027_observedfile_storage_class_name_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="LocalStorageQuota",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "quota",
                    models.BigIntegerField(
                        default=100000000, help_text="Maximum storage capacity in bytes"
                    ),
                ),
                (
                    "lab",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="local_storage_quota",
                        to="galv.lab",
                    ),
                ),
            ],
        ),
    ]
