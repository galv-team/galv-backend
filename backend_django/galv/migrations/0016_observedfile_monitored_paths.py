# Generated by Django 5.0.2 on 2024-04-12 13:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('galv', '0015_remove_lab_s3_region_alter_lab_s3_custom_domain'),
    ]

    operations = [
        migrations.AddField(
            model_name='observedfile',
            name='monitored_paths',
            field=models.ManyToManyField(blank=True, help_text='Paths that this file is on', related_name='files', to='galv.monitoredpath'),
        ),
    ]
