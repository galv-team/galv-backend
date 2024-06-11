# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import unittest
import logging

from .utils import GalvTeamResourceTestCase
from .factories import ArbitraryFileFactory, fake

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class ArbitraryFileTests(GalvTeamResourceTestCase):
    stub = 'arbitraryfile'
    factory = ArbitraryFileFactory

    def get_edit_kwargs(self):
        return {'name': f"{fake.word()} {fake.word()} {self.client.session.session_key or 'session_key'}"}

if __name__ == '__main__':
    unittest.main()
