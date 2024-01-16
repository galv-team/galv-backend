# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import unittest
import logging
import uuid

from rest_framework.reverse import reverse

from ..models import UserLevel, ALLOWED_USER_LEVELS_READ, ALLOWED_USER_LEVELS_EDIT, ALLOWED_USER_LEVELS_DELETE
from .utils import _GalvTeamResourceTestCase
from .factories import CellFactory

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class AccessLevelTests(_GalvTeamResourceTestCase):
    """
    Taking Cell as an example, we check properties of access_levels.
    Note that the actual ability to read/edit/delete is tested in test_cell.py,
    so we're only interested in whether and how we can change access_levels here.
    * Only team admins and team members can change access levels
    * If you can change the access level, you can lock yourself out
    * You can only change access levels to those allowed for that operation
    * You can refer to access_level by name or by number
    * If you don't have the appropriate access level, you can't change it
    * You can't violate the Read < Edit < Delete hierarchy
    """
    stub = 'cell'
    factory = CellFactory

    def get_edit_kwargs(self):
        return {'identifier': str(uuid.uuid4())}

    def test_access_level_change_ok(self):
        """
        * Only team admins and team members can change access levels
        """
        self.client.force_authenticate(self.user)
        resource = self.create_with_perms(read_access_level=UserLevel.TEAM_MEMBER.value)
        url = reverse(f'{self.stub}-detail', args=(resource.pk,))
        response = self.file_safe_request(
            self.client.patch,
            url,
            {'read_access_level': UserLevel.ANONYMOUS.value}
        )
        self.assertEqual(response.status_code, 200)
        resource.refresh_from_db()
        self.assertEqual(resource.read_access_level, UserLevel.ANONYMOUS.value)
        # And back again
        response = self.file_safe_request(
            self.client.patch,
            url,
            {'read_access_level': UserLevel.TEAM_MEMBER.value}
        )
        self.assertEqual(response.status_code, 200)
        resource.refresh_from_db()
        self.assertEqual(resource.read_access_level, UserLevel.TEAM_MEMBER.value)

    def test_access_level_change_fail(self):
        """
        * Only team admins and team members can change access levels
        """
        self.client.force_authenticate(self.strange_lab_admin)
        resource = self.create_with_perms(read_access_level=UserLevel.TEAM_MEMBER.value)
        url = reverse(f'{self.stub}-detail', args=(resource.pk,))
        response = self.file_safe_request(
            self.client.patch,
            url,
            {'read_access_level': UserLevel.ANONYMOUS.value}
        )
        self.assertEqual(response.status_code, 403)

    def test_access_level_change_lockout(self):
        """
        * If you can change the access level, you can lock yourself out
        * If you don't have the appropriate access level, you can't change it
        """
        self.client.force_authenticate(self.user)
        resource = self.create_with_perms(delete_access_level=UserLevel.TEAM_ADMIN.value)
        url = reverse(f'{self.stub}-detail', args=(resource.pk,))
        response = self.file_safe_request(
            self.client.patch,
            url,
            {'edit_access_level': UserLevel.TEAM_ADMIN.value}
        )
        self.assertEqual(response.status_code, 200)
        resource.refresh_from_db()
        self.assertEqual(resource.edit_access_level, UserLevel.TEAM_ADMIN.value)
        # And now we can't change it back
        response = self.file_safe_request(
            self.client.patch,
            url,
            {'edit_access_level': UserLevel.TEAM_MEMBER.value}
        )
        self.assertEqual(response.status_code, 403)

    def test_access_level_change_values(self):
        self.client.force_authenticate(self.admin)  # team admin won't run into lockout issues
        for access_type, allowed in [
            ('delete_access_level', ALLOWED_USER_LEVELS_DELETE),
            ('edit_access_level', ALLOWED_USER_LEVELS_EDIT),
            ('read_access_level', ALLOWED_USER_LEVELS_READ),
        ]:
            for level, label in UserLevel.choices:
                with self.subTest(access_type=access_type, label=label):
                    resource = self.create_with_perms(
                        read_access_level=UserLevel.ANONYMOUS.value,
                        edit_access_level=UserLevel.TEAM_MEMBER.value \
                            if access_type == 'delete_access_level' else UserLevel.TEAM_ADMIN.value,
                        delete_access_level=UserLevel.TEAM_ADMIN.value,
                    )
                    url = reverse(f'{self.stub}-detail', args=(resource.pk,))
                    response = self.file_safe_request(
                        self.client.patch,
                        url,
                        {access_type: level}
                    )
                    expected_code = 200 if UserLevel(level) in allowed else 400
                    self.assertEqual(response.status_code, expected_code)
                    if expected_code == 200:
                        resource.refresh_from_db()
                        self.assertEqual(getattr(resource, access_type), level)

    def test_access_level_hierarchies(self):
        self.client.force_authenticate(self.admin)
        resource = self.create_with_perms(
            read_access_level=UserLevel.LAB_MEMBER.value,
            edit_access_level=UserLevel.TEAM_MEMBER.value,
            delete_access_level=UserLevel.TEAM_MEMBER.value,
        )
        url = reverse(f'{self.stub}-detail', args=(resource.pk,))
        # Try to violate the hierarchy
        for access_type in ['read_access_level', 'edit_access_level']:
            with self.subTest(access_type=access_type):
                response = self.file_safe_request(
                    self.client.patch,
                    url,
                    {access_type: UserLevel.TEAM_ADMIN.value}
                )
                self.assertEqual(response.status_code, 400)
        # Verify it works if we do it all in one go
        response = self.file_safe_request(
            self.client.patch,
            url,
            {
                'read_access_level': UserLevel.TEAM_ADMIN.value,
                'edit_access_level': UserLevel.TEAM_ADMIN.value,
                'delete_access_level': UserLevel.TEAM_ADMIN.value,
            }
        )
        self.assertEqual(response.status_code, 200)
        resource.refresh_from_db()
        self.assertEqual(resource.read_access_level, UserLevel.TEAM_ADMIN.value)
        self.assertEqual(resource.edit_access_level, UserLevel.TEAM_ADMIN.value)
        self.assertEqual(resource.delete_access_level, UserLevel.TEAM_ADMIN.value)

if __name__ == '__main__':
    unittest.main()
