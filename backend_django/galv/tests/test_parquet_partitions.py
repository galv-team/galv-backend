# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
import tempfile
import unittest

from django.core.files.uploadedfile import TemporaryUploadedFile
from rest_framework import status
import logging

from rest_framework.reverse import reverse

from ..models import UserLevel
from .utils import assert_response_property, GalvTestCase
from .factories import HarvesterFactory, \
    MonitoredPathFactory, \
    ParquetPartitionFactory, fake, ObservedFileFactory

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class ParquetPartitionTests(GalvTestCase):
    stub = 'parquetpartition'
    factory = ParquetPartitionFactory

    def get_edit_kwargs(self):
        return {}

    def setUp(self):
        super().setUp()
        self.harvester = HarvesterFactory.create(name='Test Parquet Partitions', lab=self.lab)
        self.monitored_path = MonitoredPathFactory.create(
            harvester=self.harvester,
            path="/specific",
            team=self.lab_team,
            read_access_level=UserLevel.TEAM_MEMBER.value
        )
        self.file = ObservedFileFactory.create(harvester=self.harvester)
        self.file.monitored_paths.set([self.monitored_path])
        self.other_file = ObservedFileFactory.create(harvester=self.harvester)
        self.partition = ParquetPartitionFactory.create(
            observed_file=self.file,
            parquet_file=TemporaryUploadedFile(
                name=fake.file_name(),
                content_type='application/octet-stream',
                size=100_000,
                charset='utf-8'
            )
        )
        self.other_partition = ParquetPartitionFactory.create(observed_file=self.other_file)

    def test_create_rejected(self):
        for user, login in {
            'user': lambda: self.client.force_authenticate(self.user),
            'admin': lambda: self.client.force_authenticate(self.admin),
            'other': lambda: self.client.force_authenticate(self.lab_admin),
            'stranger': lambda: self.client.force_authenticate(self.strange_lab_admin),
            'anonymous': lambda: self.client.logout(),
        }.items():
            with self.subTest(user=user):
                login()
                response = self.client.post(reverse(f'{self.stub}-list'), data=self.get_edit_kwargs())
                assert_response_property(self, response, self.assertEqual, response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_list(self):
        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user), 'expected_set': [self.partition]},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin), 'expected_set': [self.partition]},
            'lab_admin': {'login': lambda: self.client.force_authenticate(self.lab_admin), 'expected_set': []},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'expected_set': []},
            'anonymous': {'login': lambda: self.client.logout(), 'expected_set': []},
        }.items():
            with self.subTest(user=user):
                details['login']()
                response = self.client.get(reverse(f'{self.stub}-list'))
                assert_response_property(self, response, self.assertEqual, response.status_code, status.HTTP_200_OK)
                self.assertEqual(len(response.json().get("results", [])), len(details['expected_set']))
                for file in details['expected_set']:
                    self.assertIn(str(file.id), [p['id'] for p in response.json().get("results", [])])

    def test_read(self):
        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user), 'code': 200},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin), 'code': 200},
            'other': {'login': lambda: self.client.force_authenticate(self.lab_admin), 'code': 403},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'code': 403},
            'anonymous': {'login': lambda: self.client.logout(), 'code': 401},
        }.items():
            with self.subTest(user=user):
                details['login']()
                response = self.client.get(reverse(f'{self.stub}-detail', args=(self.partition.id,)))
                assert_response_property(self, response, self.assertEqual, response.status_code, details['code'])
                if response.status_code == 200:
                    self.assertEqual(response.json()['id'], str(self.partition.id))
                    self.assertEqual(
                        response.json()['parquet_file'],
                        reverse(
                            f"{self.stub}-file",
                            args=(str(self.partition.id),),
                            request=response.wsgi_request
                        ),
                        "Parquet file URL should be included in the response"
                    )

    def test_update(self):
        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user)},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin)},
            'other': {'login': lambda: self.client.force_authenticate(self.lab_admin)},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin)},
            'anonymous': {'login': lambda: self.client.logout()},
        }.items():
            with self.subTest(user=user):
                details['login']()
                response = self.client.patch(reverse(f'{self.stub}-detail', args=(self.partition.id,)), data=self.get_edit_kwargs(), format='json')
                assert_response_property(self, response, self.assertEqual, response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_destroy_rejected(self):
        for user, login in {
            'user': lambda: self.client.force_authenticate(self.user),
            'admin': lambda: self.client.force_authenticate(self.admin),
            'other': lambda: self.client.force_authenticate(self.lab_admin),
            'stranger': lambda: self.client.force_authenticate(self.strange_lab_admin),
            'anonymous': lambda: self.client.logout(),
        }.items():
            with self.subTest(user=user):
                login()
                response = self.client.delete(reverse(f'{self.stub}-list'), data=self.get_edit_kwargs())
                assert_response_property(self, response, self.assertEqual, response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

if __name__ == '__main__':
    unittest.main()
