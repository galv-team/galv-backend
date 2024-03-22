# Generated by Django 5.0.2 on 2024-03-21 09:43

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('galv', '0002_datacolumntype_delete_access_level_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='datacolumn',
            name='type',
            field=models.ForeignKey(help_text='Column Type which this Column instantiates', on_delete=django.db.models.deletion.CASCADE, related_name='columns', to='galv.datacolumntype'),
        ),
        migrations.AlterField(
            model_name='monitoredpath',
            name='regex',
            field=models.TextField(blank=True, default='.*', help_text="\n    Python.re regular expression to filter files by, \n    applied to full file name starting from this Path's directory", null=True),
        ),
    ]
