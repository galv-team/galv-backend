# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import unittest
import logging

from .utils import GalvTeamResourceTestCase
from .factories import DataUnitFactory, fake

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class DataUnitTests(GalvTeamResourceTestCase):
    stub = 'dataunit'
    factory = DataUnitFactory

    def get_edit_kwargs(self):
        return {'name': fake.word()}

    def test_destroy_non_team_member(self):
        pass

    def test_destroy_team_member(self):
        pass

if __name__ == '__main__':
    unittest.main()
