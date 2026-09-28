# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import logging
import unittest

from .factories import CellFactory, CyclerTestFactory
from .utils import GalvTeamResourceTestCase

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class CyclerTestTests(GalvTeamResourceTestCase):
    stub = "cyclertest"
    factory = CyclerTestFactory

    def get_edit_kwargs(self):
        cell = CellFactory.create()
        return {"cell": cell.pk}


if __name__ == "__main__":
    unittest.main()
