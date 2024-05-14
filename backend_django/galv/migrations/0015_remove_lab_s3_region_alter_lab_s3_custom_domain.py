# Generated by Django 5.0.2 on 2024-04-12 07:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('galv', '0014_alter_lab_s3_custom_domain_alter_lab_s3_region'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='lab',
            name='s3_region',
        ),
        migrations.AlterField(
            model_name='lab',
            name='s3_custom_domain',
            field=models.TextField(blank=True, help_text='Custom domain for the S3 bucket.', null=True),
        ),
    ]
