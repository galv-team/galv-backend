# Generated by Django 5.0.2 on 2024-04-15 11:35

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("galv", "0020_alter_observedfile_state"),
    ]

    operations = [
        migrations.AlterField(
            model_name="observedfile",
            name="state",
            field=models.TextField(
                choices=[
                    ("RETRY IMPORT", "Retry Import"),
                    ("IMPORT FAILED", "Import Failed"),
                    ("UNSTABLE", "Unstable"),
                    ("GROWING", "Growing"),
                    ("STABLE", "Stable"),
                    ("IMPORTING", "Importing"),
                    ("AWAITING MAP ASSIGNMENT", "Awaiting Map Assignment"),
                    ("MAP ASSIGNED", "Map Assigned"),
                    ("IMPORTED", "Imported"),
                ],
                default="UNSTABLE",
                help_text="File status; autogenerated but can be manually set to RETRY IMPORT",
            ),
        ),
    ]
