# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
import os


class Command(BaseCommand):
    help = """
    Create superuser with login details from envvars
    DJANGO_SUPERUSER_USERNAME (default=admin),
    DJANGO_SUPERUSER_PASSWORD (required)
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "--no-input", action="store_true", help="Username for superuser"
        )
        parser.add_argument(
            "--noinput", action="store_true", help="Password for superuser"
        )

    def handle(self, *args, **options):
        password = os.getenv("DJANGO_SUPERUSER_PASSWORD", "")
        if not len(password):
            self.stdout.write(
                self.style.WARNING(
                    "No DJANGO_SUPERUSER_PASSWORD specified, creating dummy user instead of superuser."
                )
            )
            username = "placeholder"
            try:
                User.objects.get(username=username)
                self.stdout.write(
                    self.style.SUCCESS(f"User {username} already exists.")
                )
            except User.DoesNotExist:
                User.objects.create_user(
                    username=username,
                    password="placeholder",
                    is_superuser=False,
                    is_staff=False,
                    is_active=False,
                )
                self.stdout.write(self.style.SUCCESS(f"Created dummy user {username}."))
            return
        username = os.getenv("DJANGO_SUPERUSER_USERNAME", "admin")
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(
                    f"User {username} already exists: skipping user creation."
                )
            )
            return
        User.objects.create_user(
            username=username,
            password=password,
            is_superuser=True,
            is_staff=True,
            is_active=True,
        )
        self.stdout.write(self.style.SUCCESS(f"Created superuser {username}."))
