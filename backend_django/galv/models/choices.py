from django.db import models


class FileState(models.TextChoices):
    RETRY_IMPORT = "RETRY IMPORT"
    IMPORT_FAILED = "IMPORT FAILED"
    UNSTABLE = "UNSTABLE"
    GROWING = "GROWING"
    STABLE = "STABLE"
    IMPORTING = "IMPORTING"
    AWAITING_MAP_ASSIGNMENT = "AWAITING MAP ASSIGNMENT"
    MAP_ASSIGNED = "MAP ASSIGNED"
    AWAITING_STORAGE = "AWAITING STORAGE"
    IMPORTED = "IMPORTED"


class UserLevel(models.Choices):
    """
    User levels for access control.
    Team/Lab levels only make sense in the context of a Resource.
    """

    ANONYMOUS = 0
    REGISTERED_USER = 1
    LAB_MEMBER = 2
    TEAM_MEMBER = 3
    TEAM_ADMIN = 4


class ValidationStatus(models.TextChoices):
    VALID = "VALID"
    INVALID = "INVALID"
    SKIPPED = "SKIPPED"
    UNCHECKED = "UNCHECKED"
    ERROR = "ERROR"
