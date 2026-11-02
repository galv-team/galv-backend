# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import logging
import unittest

from .factories import EquipmentFamilyFactory
from .utils import GalvTeamResourceTestCase

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)


class EquipmentFamilyTests(GalvTeamResourceTestCase):
    stub = "equipmentfamily"
    factory = EquipmentFamilyFactory
    edit_kwargs = {"type": "test"}


if __name__ == "__main__":
    unittest.main()
