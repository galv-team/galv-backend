# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import unittest
import logging

from rest_framework.reverse import reverse

from .utils import GalvTestCase
from .factories import fake, GalvStorageTypeFactory, AdditionalS3StorageTypeFactory

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class StubFactory:
    def create(self, **kwargs):
        raise NotImplementedError


class StorageResourceTestCase(GalvTestCase):
    stub = "NA"
    factory = StubFactory

    def setUp(self) -> None:
        super().setUp()
        if self.__class__.__name__ == "StorageResourceTestCase":
            raise self.skipTest("This is an abstract base class")

    def get_edit_kwargs(self):
        raise NotImplementedError

    def test_create(self):
        """
        * Create requests allowed for lab admins only, and only if the lab is their lab
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 403},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 403},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 201,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 400,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 401,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-list")
                create_dict = self.dict_factory(lab=self.lab)
                response = self.client.post(
                    url,
                    {**create_dict, "lab": reverse("lab-detail", args=(self.lab.pk,))},
                )
                self.assertTrue(
                    details["response"](response),
                    msg=f"{user} create resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_list(self):
        """
        LabResourceFilter works correctly
        """
        for user, details in {
            "user": {
                "login": self.user,
                "response": lambda r: len(r.json()["results"]) == 1,
            },
            "admin": {
                "login": self.admin,
                "response": lambda r: len(r.json()["results"]) == 1,
            },
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: len(r.json()["results"]) == 1,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                # GalvStorageType is automatically created for the lab, so Strange Lab will have one
                "response": lambda r: len(r.json()["results"])
                == int(self.__class__.__name__ == "GalvStorageTypeTests"),
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: len(r.json()["results"]) == 0,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-list")
                response = self.client.get(url)
                self.assertTrue(
                    details["response"](response),
                    msg=f"{user} read resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_read(self):
        """
        Lab members can read Lab resources
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 200},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 200},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 200,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 403,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 401,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-detail", args=(self.resource.pk,))
                response = self.client.get(url)
                self.assertTrue(
                    details["response"](response),
                    msg=f"{user} read resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_update(self):
        """
        * Update requests allowed for lab admins only, and only if the lab is their lab
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 403},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 403},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 200,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 403,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 401,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-detail", args=(self.resource.pk,))
                response = self.client.patch(url, self.get_edit_kwargs())
                self.assertTrue(
                    details["response"](response),
                    msg=f"Check {user} can update resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_disable(self):
        """
        Lab admins can set enabled=False
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 403},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 403},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 200,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 403,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 401,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-detail", args=(self.resource.pk,))
                response = self.client.patch(url, {"enabled": False})
                self.assertTrue(
                    details["response"](response),
                    msg=f"{user}: disable resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_destroy(self):
        """
        * Delete requests allowed for lab admins only, and only if the lab is their lab
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 403},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 403},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 204,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 404,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 404,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-detail", args=(self.resource.pk,))
                response = self.client.delete(url)
                self.assertTrue(
                    details["response"](response),
                    msg=f"Check {user} can delete resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )


class GalvStorageTypeTests(StorageResourceTestCase):
    stub = "galvstoragetype"
    factory = GalvStorageTypeFactory

    def setUp(self) -> None:
        super().setUp()
        self.resource = self.factory.create(lab=self.lab)

    def get_edit_kwargs(self):
        return {"name": fake.word(), "priority": fake.pyint(0, 5)}

    def test_create(self):
        """
        No one may create a GalvStorageType
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 403},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 403},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 403,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 403,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 401,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-list")
                create_dict = self.dict_factory(lab=self.lab)
                response = self.client.post(url, create_dict)
                self.assertTrue(
                    details["response"](response),
                    msg=f"Check {user} can create resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_destroy(self):
        """
        No one may destroy a GalvStorageType
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 405},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 405},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.status_code == 405,
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 405,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 405,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-detail", args=(self.resource.pk,))
                response = self.client.delete(url)
                self.assertTrue(
                    details["response"](response),
                    msg=f"Check {user} can delete resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )

    def test_update_quota(self):
        """
        No one may update the quota of a GalvStorageType
        """
        for user, details in {
            "user": {"login": self.user, "response": lambda r: r.status_code == 403},
            "admin": {"login": self.admin, "response": lambda r: r.status_code == 403},
            "lab_admin": {
                "login": self.lab_admin,
                "response": lambda r: r.json()["quota_bytes"]
                > 10,  # should not have changed
            },
            "strange_lab_admin": {
                "login": self.strange_lab_admin,
                "response": lambda r: r.status_code == 403,
            },
            "anonymous": {
                "login": lambda: self.client.logout(),
                "response": lambda r: r.status_code == 401,
            },
        }.items():
            with self.subTest(user=user):
                details["login"]() if callable(
                    details["login"]
                ) else self.client.force_login(details["login"])
                url = reverse(f"{self.stub}-detail", (self.resource.pk,))
                response = self.client.patch(url, {"quota_bytes": fake.pyint(5, 10)})
                self.assertTrue(
                    details["response"](response),
                    msg=f"{user} update resources on {self.lab_team}\n{response.status_code}\n{response.data}",
                )


class AdditionalS3StorageTypeTests(StorageResourceTestCase):
    stub = "additionals3storagetype"
    factory = AdditionalS3StorageTypeFactory

    def setUp(self) -> None:
        super().setUp()
        self.resource = self.factory.create(lab=self.lab)

    def get_edit_kwargs(self):
        return {
            "name": fake.word(),
            "priority": fake.pyint(1501, 10000),
            "bucket_name": fake.word(),
            "secret_key": fake.word(),
            "access_key": fake.word(),
        }


if __name__ == "__main__":
    unittest.main()
