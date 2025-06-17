# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand
import os

from galv.models import (
    Lab,
    Team,
    AdditionalS3StorageType,
    ObservedFile,
    ColumnMapping,
    UserProxy,
    FileState,
    UserLevel,
)


class Command(BaseCommand):
    help = """
    Seed data with S3 bucket details from envvars
    DJANGO_SEED_DATA_BUCKET_NAME,
    DJANGO_SEED_DATA_BUCKET_REGION,
    DJANGO_SEED_DATA_BUCKET_KEY_ID,
    DJANGO_SEED_DATA_BUCKET_SECRET_KEY.
    """

    def handle(self, *args, **options):
        bucket_name = os.getenv("DJANGO_SEED_DATA_BUCKET_NAME")
        bucket_region = os.getenv("DJANGO_SEED_DATA_BUCKET_REGION")
        bucket_key_id = os.getenv("DJANGO_SEED_DATA_BUCKET_KEY_ID")
        bucket_secret_key = os.getenv("DJANGO_SEED_DATA_BUCKET_SECRET_KEY")
        if (
            not bucket_name
            or not bucket_region
            or not bucket_key_id
            or not bucket_secret_key
        ):
            self.stdout.write(
                self.style.WARNING(
                    "Not all required environment variables for S3 bucket are set. "
                    "You need to set "
                    "DJANGO_SEED_DATA_BUCKET_NAME, "
                    "DJANGO_SEED_DATA_BUCKET_REGION, "
                    "DJANGO_SEED_DATA_BUCKET_KEY_ID, "
                    "DJANGO_SEED_DATA_BUCKET_SECRET_KEY. "
                    "Skipping S3 bucket seeding."
                )
            )
            return

        # Create a lab if it doesn't exist
        user, create = UserProxy.objects.get_or_create(
            username="seed_data_user",
            defaults={
                "email": "seed_data_user@example.com",
            },
        )
        if create:
            self.stdout.write(
                self.style.SUCCESS("Created seed data user: seed_data_user")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS("Seed data user already exists: seed_data_user")
            )
        lab, created = Lab.objects.get_or_create(name="Seed Data Lab")
        if created:
            self.stdout.write(self.style.SUCCESS("Created lab: Seed Data Lab"))
        else:
            self.stdout.write(self.style.SUCCESS("Lab already exists: Seed Data Lab"))
        # Create a team if it doesn't exist
        team, created = Team.objects.get_or_create(name="Seed Data Team", lab=lab)
        if created:
            self.stdout.write(self.style.SUCCESS("Created team: Seed Data Team"))
        else:
            self.stdout.write(self.style.SUCCESS("Team already exists: Seed Data Team"))
        if not team.admin_group.user_set.filter(pk=user.pk).exists():
            team.admin_group.user_set.add(user)
            team.admin_group.save()
            self.stdout.write(
                self.style.SUCCESS("Added seed data user to team: Seed Data Team")
            )
        if not lab.admin_group.user_set.filter(pk=user.pk).exists():
            lab.admin_group.user_set.add(user)
            lab.admin_group.save()
            self.stdout.write(
                self.style.SUCCESS("Added seed data user to lab: Seed Data Lab")
            )

        # Create an additional S3 storage type if it doesn't exist
        storage_type, created = AdditionalS3StorageType.objects.get_or_create(
            name="Seed Data Storage",
            bucket_name=bucket_name,
            lab=lab,
            defaults={
                "region_name": bucket_region,
                "access_key": bucket_key_id,
                "secret_key": bucket_secret_key,
                "quota_bytes": 10_000_000,
                "priority": 100,
            },
        )
        if created:
            self.stdout.write(
                self.style.SUCCESS(
                    "Created additional S3 storage type: Seed Data Storage"
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "Additional S3 storage type already exists: Seed Data Storage"
                )
            )

        # Create the datafiles if they don't exist
        min_map = ColumnMapping.objects.get(name="Galv minimal")
        content_type = ContentType.objects.get_for_model(AdditionalS3StorageType)
        for file in [
            {
                "name": "Sample_HPPC_Data",
                "path": "seed_data/Sample_HPPC_Data",
                "bytes_required": 1_105_000,
                "summary": {},
                "mapping": min_map.pk,
                "png": "tmpf6x9k696.csv.png",
            },
        ]:
            f = ObservedFile.objects.filter(
                name=file["name"], _storage_object_id=storage_type.pk, team=team
            ).first()
            if f is not None:
                self.stdout.write(f"- Removing existing Observed file: {file['name']}")
                f.delete()
            ObservedFile.objects.create(
                name=file["name"],
                _storage_content_type=content_type,
                _storage_object_id=storage_type.pk,
                path=file["path"],
                bytes_required=file["bytes_required"],
                uploader=user,
                state=FileState.IMPORTED,
                summary=file["summary"],
                mapping_id=file["mapping"],
                png=file["png"],
                read_access_level=UserLevel.ANONYMOUS.value,
                team=team,
            )
            self.stdout.write(
                self.style.SUCCESS(f"Created observed file: {file['name']}")
            )
