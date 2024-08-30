# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
import tempfile
import unittest
from django.urls import reverse
from rest_framework import status
import logging

from .utils import assert_response_property, GalvTestCase
from .factories import HarvesterFactory, \
    MonitoredPathFactory, \
    ObservedFileFactory, fake, ColumnMappingFactory
from ..models import FileState, UserLevel, ObservedFile, ParquetPartition

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class ObservedFileTests(GalvTestCase):
    stub = 'observedfile'
    factory = ObservedFileFactory

    def setUp(self):
        super().setUp()
        self.harvester = HarvesterFactory.create(name='Test Files', lab=self.lab)
        self.specific_path = MonitoredPathFactory.create(
            harvester=self.harvester,
            path="/specific",
            team=self.lab_team,
            read_access_level=UserLevel.TEAM_MEMBER.value
        )
        self.other_path = MonitoredPathFactory.create(
            harvester=self.harvester,
            path="/other",
            team=self.lab_other_team,
            read_access_level=UserLevel.TEAM_MEMBER.value
        )
        self.regex_path = MonitoredPathFactory.create(
            harvester=self.harvester,
            path="/",
            regex="abc/.*",
            team=self.lab_team,
            read_access_level=UserLevel.TEAM_MEMBER.value
        )
        self.specific_files = ObservedFileFactory.create_batch(size=2, harvester=self.harvester, path_root=self.specific_path.path)
        assert ObservedFile.objects.filter(pk=self.specific_files[0].pk).exists(), "File not created"
        self.other_files = ObservedFileFactory.create_batch(size=3, harvester=self.harvester, path_root=self.other_path.path)
        self.regex_files = ObservedFileFactory.create_batch(size=6, harvester=self.harvester, path_root=f"{self.regex_path.path}/abc")
        self.other_harvester = HarvesterFactory.create(name='Test Files Other', lab=self.strange_lab)
        self.other_harvester_path = MonitoredPathFactory.create(harvester=self.other_harvester, path="/", team=self.strange_lab_team)
        self.other_harvester_files = ObservedFileFactory.create_batch(size=4, harvester=self.other_harvester, path_root=self.other_harvester_path.path)

        # assign files to paths
        for file in self.specific_files:
            file.monitored_paths.set([self.specific_path])
        for file in self.other_files:
            file.monitored_paths.set([self.other_path])
        for file in self.regex_files:
            file.monitored_paths.set([self.regex_path])
        for file in self.other_harvester_files:
            file.monitored_paths.set([self.other_harvester_path])

    def get_edit_kwargs(self):
        return {'name': fake.file_name()}
    def test_list(self):
        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user), 'expected_set': [*self.specific_files, *self.regex_files]},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin), 'expected_set': [*self.specific_files, *self.regex_files]},
            'lab_admin': {'login': lambda: self.client.force_authenticate(self.lab_admin), 'expected_set': []},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'expected_set': [*self.other_harvester_files]},
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
                response = self.client.get(reverse(f'{self.stub}-detail', args=(self.specific_files[0].id,)))
                assert_response_property(self, response, self.assertEqual, response.status_code, details['code'])
                if response.status_code == 200:
                    self.assertEqual(response.json()['id'], str(self.specific_files[0].id))

    def test_update(self):
        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user), 'code': 200},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin), 'code': 200},
            'other': {'login': lambda: self.client.force_authenticate(self.lab_admin), 'code': 403},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'code': 403},
            'anonymous': {'login': lambda: self.client.logout(), 'code': 401},
        }.items():
            with self.subTest(user=user):
                details['login']()
                response = self.client.patch(reverse(f'{self.stub}-detail', args=(self.specific_files[0].id,)), data=self.get_edit_kwargs(), format='json')
                assert_response_property(self, response, self.assertEqual, response.status_code, details['code'])

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

    def test_reimport(self):
        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user), 'code': 200},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin), 'code': 200},
            'other': {'login': lambda: self.client.force_authenticate(self.lab_admin), 'code': 403},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'code': 403},
            'anonymous': {'login': lambda: self.client.logout(), 'code': 401},
        }.items():
            with self.subTest(user=user):
                self.specific_files[0].state = FileState.IMPORTED
                self.specific_files[0].save()
                details['login']()
                response = self.client.get(reverse(f'{self.stub}-reimport', args=(self.specific_files[0].id,)))
                assert_response_property(self, response, self.assertEqual, response.status_code, details['code'])
                if response.status_code == 200:
                    self.assertEqual(response.json()['state'], FileState.RETRY_IMPORT)

    def test_create(self):
        """
        Users can upload files to the system. This is done in either a one- or two-stage process.

        In the one-stage process, the user uploads the file and provides a valid mapping in one go.
        In the two-stage process, the user uploads the file and then provides a valid mapping later.
        Only once the mapping is provided is are the file contents uploaded to Storage.
        """
        # create a minimal mapping that identifies key columns
        mapping = ColumnMappingFactory.create(map={})
        def get_upload_data(user_id):
            return {
                "id": "",
                "path": "/custom/file/path.csv",
                "name": "My CSV File",
                "uploader": str(user_id),
                "file": None,
                "mapping": str(mapping.id),
                "team": str(self.lab_team.id),
            }
        for user, details in {
            self.user: {'login': lambda: self.client.force_authenticate(self.user), 'code': 201},
            self.admin: {'login': lambda: self.client.force_authenticate(self.admin), 'code': 201},
            self.lab_admin: {'login': lambda: self.client.force_authenticate(self.lab_admin), 'code': 403},
            self.strange_lab_admin: {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'code': 400},
            'anonymous': {'login': lambda: self.client.logout(), 'code': 401},
        }.items():
            with tempfile.TemporaryFile() as f:
                f.write(b"ElapsedTime_s,Current_A,Voltage_V\n1,2,3\n2,2,3\n3,2,3\n4,2,3\n5,2,3\n6,2,3\n7,2,3\n8,2,3\n9,2,3\n10,2,3\n11,3,3\n")
                f.seek(0)
                with self.subTest(user=user if isinstance(user, str) else user.username):
                    details["login"]()
                    data = {**get_upload_data(user if isinstance(user, str) else user.id), "file": f}
                    response = self.client.post(reverse(f'{self.stub}-list'), data=data, format='multipart')
                    assert_response_property(self, response, self.assertEqual, response.status_code, details['code'])

        with self.subTest("Two-stage upload"):
            observed_file = None
            with self.subTest("Stage one - no mapping"):
                with tempfile.TemporaryFile() as f:
                    f.write(
                        b"ElapsedTime_s,Current_A,Voltage_V\n1,2,3\n2,2,3\n3,2,3\n4,2,3\n5,2,3\n6,2,3\n7,2,3\n8,2,3\n9,2,3\n10,2,3\n11,3,3\n")
                    f.seek(0)
                    self.client.force_authenticate(self.user)
                    data = {**get_upload_data(self.user.id), "file": f}
                    del data['mapping']
                    response = self.client.post(
                        reverse(f'{self.stub}-list'),
                        data=data,
                        format='multipart'
                    )
                    assert_response_property(self, response, self.assertEqual, response.status_code, 201)
                    self.assertIn("id", response.json(), response.data)
                    observed_file = ObservedFile.objects.get(pk=response.data["id"])
                    self.assertEqual(observed_file.state, FileState.AWAITING_MAP_ASSIGNMENT)
                    self.assertFalse(ParquetPartition.objects.filter(observed_file=observed_file).exists())

            with self.subTest("Stage two - with mapping"):
                if observed_file is None:
                    self.fail("ObservedFile not created in stage one.")
                with tempfile.TemporaryFile() as f:
                    f.write(b"ElapsedTime_s,Current_A,Voltage_V\n1,2,3\n2,2,3\n3,2,3\n4,2,3\n5,2,3\n6,2,3\n7,2,3\n8,2,3\n9,2,3\n10,2,3\n11,3,3\n")
                    f.seek(0)
                    response = self.client.post(
                        reverse(f'{self.stub}-list'),
                        {**get_upload_data(self.user.id), "target_file_id": str(observed_file.id), "file": f},  # includes the mapping this time
                        format='multipart'
                    )
                    assert_response_property(self, response, self.assertEqual, response.status_code, 201)
                    self.assertEqual(response.json()["id"], str(observed_file.id))
                    self.assertEqual(response.json()["state"], FileState.IMPORTED)
                    self.assertTrue(ParquetPartition.objects.filter(observed_file=observed_file).exists())


if __name__ == '__main__':
    unittest.main()
