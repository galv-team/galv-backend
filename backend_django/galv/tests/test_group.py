# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import unittest
from django.urls import reverse
from rest_framework import status
import logging

from ..models import Team
from .utils import assert_response_property, APITestCaseWrapper
from .factories import UserFactory, LabFactory, TeamFactory

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


"""
* Lab admins can create teams for their own lab
* Lab admins can add/remove users to/from their lab and its teams
    * Labs must have at least one admin
* Team admins can add/remove users to/from their team
* Lab members can view their lab
* Lab members can view their lab's teams
"""


class GroupTests(APITestCaseWrapper):
    def setUp(self):
        self.lab = LabFactory.create(name="Test Lab")
        self.lab_team = TeamFactory.create(name="Test Lab Team", lab=self.lab)
        self.lab_other_team = TeamFactory.create(
            name="Test Lab Other Team", lab=self.lab
        )
        self.strange_lab = LabFactory.create(name="Strange Lab")
        self.admin = UserFactory.create(username="test_group_admin")
        self.lab.admin_group.user_set.add(self.admin)
        self.user = UserFactory.create(username="test_group_user")
        self.lab_team.member_group.user_set.add(self.user)
        self.colleague = UserFactory.create(username="test_group_colleague")
        self.lab_team.member_group.user_set.add(self.colleague)
        self.associate = UserFactory.create(username="test_group_associate")
        self.lab_other_team.member_group.user_set.add(self.associate)
        self.lab.admin_group.save()
        self.lab_team.member_group.save()

    def test_list_own_lab(self):
        """
        * Lab members can view their lab
        """
        self.client.force_authenticate(self.user)
        result = self.client.get(reverse("lab-list"), format="json")
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_200_OK
        )
        results = result.json().get("results", [])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], self.lab.name)

    def test_list_own_lab_teams(self):
        """
        * Lab members can view their own teams
        """
        self.client.force_authenticate(self.user)
        result = self.client.get(reverse("team-list"), format="json")
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_200_OK
        )
        results = result.json().get("results", [])
        self.assertGreaterEqual(len(results), 1)
        team_ids = [t["id"] for t in results]
        self.assertIn(self.lab_team.id, team_ids)

    def test_lab_admins_can_see_lab_teams(self):
        """
        * Lab admins can view their lab teams
        """
        self.client.force_authenticate(self.admin)
        result = self.client.get(reverse("team-list"), format="json")
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_200_OK
        )
        results = result.json().get("results", [])
        self.assertGreaterEqual(len(results), 2)
        team_ids = [t["id"] for t in results]
        self.assertIn(self.lab_team.id, team_ids)
        self.assertIn(self.lab_other_team.id, team_ids)
        for t in team_ids:
            self.assertEqual(
                Team.objects.get(id=t).lab, self.lab, msg="Found team from another lab"
            )

    def test_lab_admins_can_create_teams(self):
        """
        * Lab admins can create teams for their own lab
        """
        self.client.force_authenticate(self.admin)
        body = {"name": "new_team", "lab": self.lab.id}
        result = self.client.post(reverse("team-list"), body, format="json")
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_201_CREATED
        )
        j = result.json()
        self.assertEqual(j["name"], body["name"])
        self.assertEqual(len(j["member_group"]), 0)
        self.assertEqual(len(j["admin_group"]), 0)

    def test_lab_admins_cannot_create_teams_elsewhere(self):
        """
        * Lab admins can create teams for their own lab
        """
        self.client.force_authenticate(self.admin)
        body = {"name": "new_team", "lab": self.strange_lab.id}
        result = self.client.post(reverse("team-list"), body, format="json")
        assert_response_property(
            self,
            result,
            self.assertEqual,
            result.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_lab_admins_can_add_and_remove_admins(self):
        """
        * Lab admins can add/remove users to/from their lab and its teams
        """
        self.client.force_authenticate(self.admin)
        body = {"admin_group": [self.admin.id, self.associate.id]}
        result = self.client.patch(
            reverse("lab-detail", args=(self.lab.id,)), body, format="json"
        )
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_200_OK
        )
        self.assertIn(
            self.associate.id,
            [u["id"] for u in self.collect_results(result.json()["admin_group"])],
        )

        body = {"admin_group": [self.admin.id]}
        result = self.client.patch(
            reverse("lab-detail", args=(self.lab.id,)), body, format="json"
        )
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_200_OK
        )
        self.assertNotIn(
            self.associate.id,
            [u["id"] for u in self.collect_results(result.json()["admin_group"])],
        )

    def test_lab_admins_cannot_add_admins_elsewhere(self):
        """
        * Lab admins can add/remove users to/from their lab and its teams
        """
        self.client.force_authenticate(self.admin)
        body = {"admin_group": [self.admin.id, self.associate.id]}
        result = self.client.patch(
            reverse("lab-detail", args=(self.strange_lab.id,)), body, format="json"
        )
        assert_response_property(
            self,
            result,
            self.assertEqual,
            result.status_code,
            status.HTTP_403_FORBIDDEN,
        )

    def test_lab_admins_cannot_remove_last_admin(self):
        """
        * Labs must have at least one admin
        """
        self.client.force_authenticate(self.admin)
        body = {"admin_group": []}
        result = self.client.patch(
            reverse("lab-detail", args=(self.lab.id,)), body, format="json"
        )
        assert_response_property(
            self,
            result,
            self.assertEqual,
            result.status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def _change_groups(self, body):
        result = self.client.patch(
            reverse("team-detail", args=(self.lab_team.id,)), body, format="json"
        )
        assert_response_property(
            self, result, self.assertEqual, result.status_code, status.HTTP_200_OK
        )
        self.assertIn(
            self.associate.id,
            [u["id"] for u in self.collect_results(result.json()["admin_group"])],
        )
        self.assertIn(
            self.associate.id,
            [u["id"] for u in self.collect_results(result.json()["member_group"])],
        )

    def test_lab_admins_can_change_team_groups(self):
        """
        * Lab admins can add admins to their lab's teams
        """
        self.lab_team.admin_group.user_set.set([])
        self.lab_team.member_group.user_set.set([])
        self.client.force_authenticate(self.admin)
        body = {
            "admin_group": [self.admin.id, self.associate.id],
            "member_group": [self.user.id, self.associate.id],
        }
        return self._change_groups(body)

    def test_team_admins_can_change_team_groups(self):
        """
        * Team admins can add/remove users to/from their team
        """
        self.lab_team.admin_group.user_set.set([self.user])
        self.lab_team.member_group.user_set.set([])
        self.client.force_authenticate(self.user)
        body = {
            "admin_group": [self.user.id, self.associate.id],
            "member_group": [self.associate.id],
        }
        return self._change_groups(body)

    def test_team_members_cannot_change_team_groups(self):
        """
        * Team members should not be able to change team groups
        """
        self.lab_team.admin_group.user_set.set([])
        self.lab_team.member_group.user_set.set([self.user])
        self.client.force_authenticate(self.user)
        body = {
            "admin_group": [self.user.id, self.associate.id],
            "member_group": [self.associate.id],
        }
        result = self.client.patch(
            reverse("team-detail", args=(self.lab_team.id,)), body, format="json"
        )
        assert_response_property(
            self,
            result,
            self.assertEqual,
            result.status_code,
            status.HTTP_403_FORBIDDEN,
        )


if __name__ == "__main__":
    unittest.main()
