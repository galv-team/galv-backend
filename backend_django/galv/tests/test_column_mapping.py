# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
import unittest

from rest_framework import status
import logging

from rest_framework.reverse import reverse

from .utils import assert_response_property, GalvTestCase
from .factories import ColumnMappingFactory, DataColumnTypeFactory, ObservedFileFactory, MonitoredPathFactory

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class ColumnMappingTests(GalvTestCase):
    stub = 'columnmapping'
    factory = ColumnMappingFactory

    def get_edit_kwargs(self):
        return {}

    def test_create(self):
        self.client.force_authenticate(self.user)
        url = reverse(f'{self.stub}-list')
        required_cols = DataColumnTypeFactory.create_batch(size=3, is_required=True)

        def check_response(response, *args, **kwargs):
            assertion = kwargs.pop('assertion', self.assertEqual)
            msg = kwargs.pop('msg', f"Check column mapping report received: [{response.status_code}] {response.json()}")
            assertion(*args, **kwargs, msg=msg)

        for mapping in [
            {
                'name': 'ok_valid',
                'map': {col.name: {'column_type': col.pk} for col in required_cols},
                'checks': [
                    lambda r: check_response(r, r.status_code, status.HTTP_201_CREATED),
                ]
            },
            {
                'name': 'ok_invalid',
                'map': {},
                'checks': [
                    lambda r: check_response(r, r.status_code, status.HTTP_201_CREATED)
                ]
            },
            {
                'name': 'error_no_col_type',
                'map': {'col': {'new_name': 'test'}},
                'checks': [
                    lambda r: check_response(r, r.status_code, status.HTTP_400_BAD_REQUEST)
                ]
            },
            {
                'name': 'error_duplicate_col',
                'map': {
                    'col': {'new_name': 'test', 'column_type': required_cols[0].pk},
                    'col2': {'new_name': 'test', 'column_type': required_cols[1].pk}
                },
                'checks': [
                    lambda r: check_response(r, r.status_code, status.HTTP_400_BAD_REQUEST)
                ]
            },
            {
                'name': 'error_map_to_key',
                'map': {
                    'col': {'new_name': 'test', 'column_type': required_cols[0].pk},
                    'test': {'new_name': 'x', 'column_type': required_cols[1].pk}
                },
                'checks': [
                    lambda r: check_response(r, r.status_code, status.HTTP_400_BAD_REQUEST),
                ]
            }
        ]:
            with self.subTest(mapping=mapping['name']):
                response = self.client.post(
                    url,
                    {'name': mapping['name'], 'map': mapping['map'], 'team': self.lab_team.pk},
                    format='json'
                )
                for check in mapping['checks']:
                    check(response)

    def test_destroy_rejected(self):
        mapping = ColumnMappingFactory.create(team=self.lab_team)
        f = ObservedFileFactory.create(mapping=mapping)
        p = MonitoredPathFactory.create(team=self.lab_team)
        f.monitored_paths.add(p)

        for user, details in {
            'user': {'login': lambda: self.client.force_authenticate(self.user), 'status': status.HTTP_400_BAD_REQUEST},
            'admin': {'login': lambda: self.client.force_authenticate(self.admin), 'status': status.HTTP_400_BAD_REQUEST},
            'other': {'login': lambda: self.client.force_authenticate(self.lab_admin), 'status': status.HTTP_403_FORBIDDEN},
            'stranger': {'login': lambda: self.client.force_authenticate(self.strange_lab_admin), 'status': status.HTTP_403_FORBIDDEN},
            'anonymous': {'login': lambda: self.client.logout(), 'status': status.HTTP_401_UNAUTHORIZED},
        }.items():
            with self.subTest(user=user):
                details['login']()
                response = self.client.delete(reverse(f'{self.stub}-detail', args=[mapping.pk]))
                assert_response_property(self, response, self.assertEqual, response.status_code, details['status'])

        # Should be able to destroy the mapping if the file is deleted
        f.delete()
        self.client.force_authenticate(self.user)
        response = self.client.delete(reverse(f'{self.stub}-detail', args=[mapping.pk]))
        assert_response_property(self, response, self.assertEqual, response.status_code, status.HTTP_204_NO_CONTENT)

if __name__ == '__main__':
    unittest.main()
