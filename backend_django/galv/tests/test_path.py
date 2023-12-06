# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
import unittest
import logging

from rest_framework.reverse import reverse

from .utils import GalvTeamResourceTestCase, assert_response_property
from .factories import MonitoredPathFactory, fake, HarvesterFactory

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class MonitoredPathTests(GalvTeamResourceTestCase):
    stub = 'monitoredpath'
    factory = MonitoredPathFactory
    harvester = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.raw_dict_factory = self.dict_factory
        self.dict_factory = self._dict_factory

    def get_edit_kwargs(self):
        return {'path': fake.file_path(depth=6)}

    def create_with_perms(self, **perms):
        if not self.harvester:
            self.harvester = HarvesterFactory(lab=self.lab)
        return self.factory(harvester=self.harvester, team=self.lab_team, **perms)

    def _dict_factory(self, *args, **kwargs):
        """
        Inject harvester kwarg into dict_factory
        """
        return self.raw_dict_factory(*args, **kwargs, harvester={'uuid': str(self.harvester.uuid)})

    def test_create_team_member(self):
        """
        * Create requests allowed if:
            * user is ADMIN of the team
        """
        self.client.force_authenticate(self.user)
        url = reverse(f'{self.stub}-list')
        create_dict = self.dict_factory(team={'name': self.lab_team.name, 'lab': self.lab_team.lab})
        response = self.file_safe_request(self.client.post, url, create_dict)
        assert_response_property(
            self, response, self.assertEqual, response.status_code,
            400, msg=f"Check {self.user.username} cannot create monitored paths on {self.lab_team}"
        )
        self.client.force_authenticate(self.admin)
        url = reverse(f'{self.stub}-list')
        create_dict = self.dict_factory(team={'name': self.lab_team.name, 'lab': self.lab_team.lab})
        response = self.file_safe_request(self.client.post, url, create_dict)
        assert_response_property(
            self, response, self.assertEqual, response.status_code,
            201, msg=f"Check {self.admin.username} can create resources on {self.lab_team}"
        )

if __name__ == '__main__':
    unittest.main()
