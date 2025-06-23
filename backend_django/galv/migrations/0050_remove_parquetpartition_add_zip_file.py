from django.db import migrations
import galv.fields

class Migration(migrations.Migration):
    dependencies = [
        ("galv", "0049_alter_additionals3storagetype_location"),
    ]

    operations = [
        migrations.AddField(
            model_name="observedfile",
            name="zip_file",
            field=galv.fields.LabDependentStorageFileField(
                null=True,
                blank=True,
                help_text="Zipped CSV data",
                upload_to="",
            ),
        ),
        migrations.DeleteModel(
            name="ParquetPartition",
        ),
    ]
