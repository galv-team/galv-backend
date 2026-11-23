# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import logging
import unittest
import uuid

from .factories import CellFactory
from .utils import GalvTeamResourceTestCase

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class CellTests(GalvTeamResourceTestCase):
    stub = "cell"
    factory = CellFactory

    def get_edit_kwargs(self):
        return {"identifier": str(uuid.uuid4())}


if __name__ == "__main__":
    unittest.main()
