# Generated by Django 5.0.2 on 2024-04-23 11:32

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('galv', '0024_alter_columnmapping_map'),
    ]

    operations = [
        migrations.RenameField(
            model_name='arbitraryfile',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='cell',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='cellfamily',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='columnmapping',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='cyclertest',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='equipment',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='equipmentfamily',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='experiment',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='harvester',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='monitoredpath',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='observedfile',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='parquetpartition',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='schedule',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='schedulefamily',
            old_name='uuid',
            new_name='id',
        ),
        migrations.RenameField(
            model_name='validationschema',
            old_name='uuid',
            new_name='id',
        ),
    ]
