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
    ParquetPartition,
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
                "location": "/",
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
        content_type = ContentType.objects.get_for_model(AdditionalS3StorageType)
        for file in [
            {
                "name": "IDF Example",
                "path": "seed_data/idf-example.idf",
                "bytes_required": 1_105_000,
                "summary": {
                    "amps": {
                        "0": "-3.61355E-05",
                        "1": "-3.61355E-05",
                        "2": "-3.61355E-05",
                        "3": "-3.61355E-05",
                        "4": "-3.61355E-05",
                        "5": "-3.61355E-05",
                        "6": "-3.61355E-05",
                        "7": "-5.14893E-05",
                        "8": "-5.14893E-05",
                        "9": "-3.61355E-05",
                    },
                    "volts": {
                        "0": "4.08131E+00",
                        "1": "4.08131E+00",
                        "2": "4.08131E+00",
                        "3": "4.08131E+00",
                        "4": "4.08131E+00",
                        "5": "4.08131E+00",
                        "6": "4.08131E+00",
                        "7": "4.08131E+00",
                        "8": "4.08131E+00",
                        "9": "4.08131E+00",
                    },
                    "test_time": {
                        "0": "1.00000E-01",
                        "1": "3.00000E-01",
                        "2": "6.00000E-01",
                        "3": "1.10000E+00",
                        "4": "2.00000E+00",
                        "5": "3.70000E+00",
                        "6": "7.00000E+00",
                        "7": "1.21000E+01",
                        "8": "1.72000E+01",
                        "9": "2.23000E+01",
                    },
                },
                "mapping": ColumnMapping.objects.get(name="Ivium .idf"),
                "png": "tmpmlwszjcd.idf.png",
                "parquet_partitions": [
                    "part.0.parquet",
                    "part.1.parquet",
                ],
            },
            {
                "name": "MPR Example",
                "path": "seed_data/mpr-example.mpr",
                "bytes_required": 1_105_000,
                "summary": {
                    "Ns": {
                        "0": 0,
                        "1": 0,
                        "2": 0,
                        "3": 0,
                        "4": 0,
                        "5": 0,
                        "6": 0,
                        "7": 1,
                        "8": 1,
                        "9": 1,
                    },
                    "I/mA": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Ece/V": {
                        "0": -0.0005670877,
                        "1": -0.0005097688,
                        "2": -0.0004142373,
                        "3": -0.0006817254,
                        "4": -0.0006244065,
                        "5": -0.0005670877,
                        "6": -0.0006435128,
                        "7": -0.0005670877,
                        "8": -0.0004906625,
                        "9": -0.0006435128,
                    },
                    "Ewe/V": {
                        "0": 0.1234872192,
                        "1": 0.123544544,
                        "2": 0.12350633,
                        "3": 0.1234107837,
                        "4": 0.1234489977,
                        "5": 0.1234107837,
                        "6": 0.1234107837,
                        "7": 0.1233534589,
                        "8": 0.1234681085,
                        "9": 0.1235254332,
                    },
                    "flags": {
                        "0": 3,
                        "1": 3,
                        "2": 3,
                        "3": 3,
                        "4": 3,
                        "5": 3,
                        "6": 3,
                        "7": 35,
                        "8": 3,
                        "9": 3,
                    },
                    "time/s": {
                        "0": 0.0,
                        "1": 9.9999997474,
                        "2": 19.9999994948,
                        "3": 29.9999992421,
                        "4": 39.9999989895,
                        "5": 49.9999987369,
                        "6": 59.9997984843,
                        "7": 59.9999984843,
                        "8": 89.9999977264,
                        "9": 119.9999969685,
                    },
                    "<Ece>/V": {
                        "0": -0.0005670877,
                        "1": -0.0005097688,
                        "2": -0.0004142373,
                        "3": -0.0006817254,
                        "4": -0.0006244065,
                        "5": -0.0005670877,
                        "6": -0.0006435128,
                        "7": -0.0005670877,
                        "8": -0.0004906625,
                        "9": -0.0006435128,
                    },
                    "I Range": {
                        "0": 14,
                        "1": 14,
                        "2": 14,
                        "3": 14,
                        "4": 14,
                        "5": 14,
                        "6": 14,
                        "7": 14,
                        "8": 14,
                        "9": 14,
                    },
                    "dq/mA.h": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "freq/Hz": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "z cycle": {
                        "0": 0,
                        "1": 0,
                        "2": 0,
                        "3": 0,
                        "4": 0,
                        "5": 0,
                        "6": 0,
                        "7": 0,
                        "8": 0,
                        "9": 0,
                    },
                    "|Ece|/V": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "|Z|/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "|Zce|/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "control/mA": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "half cycle": {
                        "0": 0,
                        "1": 0,
                        "2": 0,
                        "3": 0,
                        "4": 0,
                        "5": 0,
                        "6": 0,
                        "7": 0,
                        "8": 0,
                        "9": 0,
                    },
                    "(Q-Qo)/mA.h": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Re(Zce)/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "-Im(Zce)/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Phase(Z)/deg": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "|Energy|/W.h": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "|Zwe-ce|/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Phase(Zce)/deg": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Re(Zwe-ce)/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "-Im(Zwe-ce)/Ohm": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Energy charge/W.h": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Phase(Zwe-ce)/deg": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Energy discharge/W.h": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Capacitance charge/µF": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Q charge/discharge/mA.h": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                    "Capacitance discharge/µF": {
                        "0": 0.0,
                        "1": 0.0,
                        "2": 0.0,
                        "3": 0.0,
                        "4": 0.0,
                        "5": 0.0,
                        "6": 0.0,
                        "7": 0.0,
                        "8": 0.0,
                        "9": 0.0,
                    },
                },
                "mapping": ColumnMapping.objects.get(name="Biologic .mpr"),
                "png": "tmps61lcjpc.mpr.png",
                "parquet_partitions": [
                    "part.0_dRnVqa3.parquet",
                ],
            },
        ]:
            f = ObservedFile.objects.filter(
                name=file["name"], _storage_object_id=storage_type.pk, team=team
            ).first()
            if f is not None:
                self.stdout.write(f"- Removing existing Observed file: {file['name']}")
                f.delete(
                    delete_png=False
                )  # Need to prevent deletion of png and parquet files
            new_file = ObservedFile.objects.create(
                name=file["name"],
                _storage_content_type=content_type,
                _storage_object_id=storage_type.pk,
                path=file["path"],
                bytes_required=file["bytes_required"],
                uploader=user,
                state=FileState.IMPORTED,
                summary=file["summary"],
                mapping=file["mapping"],
                read_access_level=UserLevel.ANONYMOUS.value,
                team=team,
                png=file["png"],
            )
            for i, p in enumerate(file["parquet_partitions"]):
                ParquetPartition.objects.create(
                    observed_file=new_file,
                    partition_number=i,
                    parquet_file=p,
                )
            new_file.state = (
                FileState.IMPORTED
            )  # ColumnMapping.save() tries to overwrite this
            new_file.save()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Created observed file: {file['name']} - {new_file.pk} (partitions: {len(file['parquet_partitions'])}; {file['png']})"
                )
            )
