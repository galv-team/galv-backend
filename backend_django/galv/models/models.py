# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
import os
import re

import jsonschema
from django.conf import settings
from django.core.files.storage import Storage
from django.db import models
from django.test import RequestFactory
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.contrib.postgres.fields import ArrayField
from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import User, Group, AnonymousUser
import random
from jsonschema.exceptions import _WrappedReferencingError
from rest_framework import serializers

from .choices import FileState, UserLevel, ValidationStatus

from .utils import CustomPropertiesModel, JSONModel, LDSources, render_pybamm_schedule, UUIDModel, \
    combine_rdf_props, TimestampedModel
from .autocomplete_entries import *
from ..fields import LabDependentStorageFileField
from ..storages import LocalDataStorage, S3DataStorage

ALLOWED_USER_LEVELS_DELETE = [UserLevel(v) for v in [UserLevel.TEAM_ADMIN, UserLevel.TEAM_MEMBER]]
ALLOWED_USER_LEVELS_EDIT_PATH = [UserLevel(v) for v in [UserLevel.TEAM_ADMIN, UserLevel.TEAM_MEMBER]]
ALLOWED_USER_LEVELS_EDIT = [UserLevel(v) for v in [
    UserLevel.TEAM_ADMIN,
    UserLevel.TEAM_MEMBER,
    UserLevel.LAB_MEMBER,
    UserLevel.REGISTERED_USER
]]
ALLOWED_USER_LEVELS_READ = [UserLevel(v) for v in [
    UserLevel.TEAM_ADMIN,
    UserLevel.TEAM_MEMBER,
    UserLevel.LAB_MEMBER,
    UserLevel.REGISTERED_USER,
    UserLevel.ANONYMOUS
]]

DATA_TYPES = [
    "int",
    "float",
    "str",
    "bool",
    "datetime64[ns]",
]


VALIDATION_MOCK_ENDPOINT = "/validation_mock_request_target/"


class UserAuthDetails:
    """
    A simple class to hold user authentication details.
    """
    def __init__(
            self,
            is_authenticated: bool = False,
            is_approved: bool = False,
            is_harvester: bool = False,
            is_lab_admin: bool = False,
            lab_ids=None,
            writeable_lab_ids=None,
            team_ids=None,
            writeable_team_ids=None
    ):
        if lab_ids is None:
            lab_ids = set()
        if writeable_lab_ids is None:
            writeable_lab_ids = set()
        if team_ids is None:
            team_ids = set()
        if writeable_team_ids is None:
            writeable_team_ids = set()

        self.is_authenticated = is_authenticated
        self.is_approved = is_approved
        self.is_harvester = is_harvester
        self.is_lab_admin = is_lab_admin
        self.lab_ids = lab_ids|writeable_lab_ids
        self.writeable_lab_ids = writeable_lab_ids
        self.team_ids = team_ids|writeable_team_ids
        self.writeable_team_ids = writeable_team_ids


def get_user_auth_details(request):
    """
    Overwrite DRF ViewSet.perform_authentication to add user authentication details to the request object.

    This saves us from having to query the database for this information in every view,
    which was previously done in the `get_permissions` method of the viewsets.

    This cannot be middleware because DRF doesn't authenticate users until after middleware is run.
    """
    # Code to be executed for each request before
    # the view (and later middleware) are called.
    if getattr(request, "user_auth_details", None) is not None:
        return request.user_auth_details

    is_harvester = isinstance(request.user, HarvesterUser)

    # Team membership is always explicitly set
    team_ids = set()
    write_team_ids = set()
    # Lab membership inherits from team membership,
    # but lab admin rights are explicity declared.
    lab_ids = set()
    write_lab_ids = set()

    if request.user is not None:
        if is_harvester:
            # Harvesters only ever have read access, and belong to any team that owns a monitored path
            for values in request.user.harvester.monitored_paths.values('team__pk', 'team__lab__pk'):
                team_ids.add(values['team__pk'])
                lab_ids.add(values['team__lab__pk'])
        else:
            for g in request.user.groups.values(
                    'editable_team__pk', 'readable_team__pk', 'editable_lab__pk',
                    'editable_team__lab__pk', 'readable_team__lab__pk'
            ):
                if g['editable_team__pk'] is not None:
                    write_team_ids.add(g['editable_team__pk'])
                    lab_ids.add(g['editable_team__lab__pk'])
                elif g['readable_team__pk'] is not None:
                    team_ids.add(g['readable_team__pk'])
                    lab_ids.add(g['readable_team__lab__pk'])
                elif g['editable_lab__pk'] is not None:
                    write_lab_ids.add(g['editable_lab__pk'])

    request.user_auth_details = UserAuthDetails(
        is_authenticated=request.user.is_authenticated,
        is_approved=len(lab_ids|write_lab_ids) > 0,
        is_harvester=is_harvester,
        is_lab_admin=len(write_lab_ids) > 0,
        lab_ids=lab_ids,
        writeable_lab_ids=write_lab_ids,
        team_ids=team_ids,
        writeable_team_ids=write_team_ids,
    )

    return get_user_auth_details(request)


class UserActivation(TimestampedModel):
    """
    Model to store activation tokens for users
    """
    token_length = 8
    user = models.OneToOneField(
        to=User,
        on_delete=models.CASCADE,
        null=False,
        blank=False,
        related_name="activation"
    )
    token = models.CharField(
        max_length=token_length,
        null=True,
        blank=True
    )
    token_update_date = models.DateTimeField(
        null=True,
        blank=True
    )
    redemption_date = models.DateTimeField(
        null=True,
        blank=True
    )

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        super(UserActivation, self).save(force_insert, force_update, using, update_fields)
        if not self.user.is_active:
            if self.token is None or self.get_is_expired():
                self.generate_token()

    def send_email(self, request):
        from django.core.mail import send_mail
        print(f"Sending activation email for {self.user.username}")
        send_mail(
            'Galv account activation',
            (
                f'Your activation token is {self.token}\n\n'
                f"Your token is valid for {int(settings.USER_ACTIVATION_TOKEN_EXPIRY_S / 60)} minutes.\n\n"
                f"Galv administrative team."
            ),
            settings.DEFAULT_FROM_EMAIL,
            [self.user.email],
            fail_silently=False,
        )

    def generate_token(self):
        self.token = get_random_string(length=self.token_length, allowed_chars='1234567890')
        self.token_update_date = timezone.now()
        self.save()

    def get_is_expired(self) -> bool:
        return self.token_update_date is None or \
            (timezone.now() - self.token_update_date).total_seconds() > settings.USER_ACTIVATION_TOKEN_EXPIRY_S

    def activate_user(self):
        if self.get_is_expired():
            self.generate_token()
            raise ValueError("Activation token expired. A new token has been generated and emailed to you.")
        if self.user.is_active:
            raise RuntimeError("User already active")
        self.user.is_active = True
        self.user.save()
        self.redemption_date = timezone.now()
        self.save()

# Proxy User and Group models so that we can apply DRYPermissions
class UserProxy(User):
    class Meta:
        proxy = True

    @staticmethod
    def has_create_permission(request):
        return True

    @staticmethod
    #@allow_staff_or_superuser
    def has_read_permission(request):
        return request.user.is_authenticated

    @staticmethod
    #@allow_staff_or_superuser
    def has_write_permission(request):
        return request.user.is_authenticated

    def has_object_write_permission(self, request):
        return self == request.user

    #@allow_staff_or_superuser
    def has_object_read_permission(self, request):
        """
        Users can read their own details, or the details of any user in a lab they are a member of.
        Lab admins can read the details of any user.
        """
        if self == request.user or get_user_auth_details(request).is_lab_admin:
            return True
        for g in GroupProxy.objects.filter(user=self):
            t = g.owner
            if isinstance(t, Team) and t.lab.pk in get_user_auth_details(request).lab_ids:
                return True
        return False

    def has_object_destroy_permission(self, request):
        if self != request.user:
            return False
        for lab in get_user_auth_details(request).writeable_lab_ids:
            if Lab.objects.get(pk=lab).admin_group.user_set.count() == 1:
                return False
        return True

class GroupProxy(Group):
    class Meta:
        proxy = True

    @staticmethod
    def has_create_permission(request):
        return False

    @staticmethod
    def has_destroy_permission(request):
        return False

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return True

    def get_owner(self):
        if hasattr(self, 'editable_lab'):
            return self.editable_lab
        if hasattr(self, 'editable_team'):
            return self.editable_team
        if hasattr(self, 'readable_team'):
            return self.readable_team
        return None

    @property
    def owner(self):
        return self.get_owner()

    #@allow_staff_or_superuser
    def has_object_write_permission(self, request):
        owner = self.get_owner()
        if owner is not None:
            return owner.has_object_write_permission(request)# or self in request.user.groups.all()
        return False

    #@allow_staff_or_superuser
    def has_object_read_permission(self, request):
        owner = self.get_owner()
        if owner is not None:
            return owner.has_object_read_permission(request) or self in request.user.groups.all()
        return self in request.user.groups.all()


class StorageError(Exception):
    pass

class StorageLockedError(StorageError):
    pass

class StorageFullError(StorageError):
    pass

class StorageReconstructionError(StorageError):
    pass

class StorageConfigurationError(StorageError):
    pass


class _StorageTypeConsumerModel(UUIDModel):
    """
    We can't define a ForeignKey to an abstract model,
    so this class allows us to define a ForeignKey to any _StorageType subclass.
    """
    _storage_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    _storage_object_id = models.UUIDField(null=True)
    storage_type = GenericForeignKey('_storage_content_type', '_storage_object_id')
    # This is a workaround for not being able to access the file we're trying to save in the pre_save hook
    # for the FileField.
    # Instead, we make sure we populate this field _before_ adding the actual file.
    # If overwriting a file with a smaller file, this will be negative.
    bytes_required = models.BigIntegerField(default=0)
    view_name = ""  # This is set by the subclass and is used to create the URL for the object via DRF's reverse()

    def _get_lab(self):
        """
        Return the Lab that this object belongs to.

        This is a helper method to allow get_storage to function across different models.
        """
        raise NotImplementedError

    def get_storage(self, saving=False):
        """
        Return a *Storage() instance.

        Implementations will point to the Lab's get_storage method.
        That method will set the storage_type attribute of the instance if it is not already set.
        """
        return self._get_lab().get_storage(self, saving)

    class Meta:
        abstract = True


class _StorageType(UUIDModel):
    name = models.TextField(null=True, blank=True)
    lab = models.ForeignKey('Lab', related_name="storage_%(class)s", on_delete=models.CASCADE)
    enabled = models.BooleanField(default=True, help_text="Whether this storage type is enabled for writing to")
    quota = models.BigIntegerField(help_text="Maximum storage capacity in bytes")
    priority = models.SmallIntegerField(
        default=0,
        help_text="Priority for storage allocation. Higher values are higher priority."
    )

    # This isn't DRY, but we have to repeat stuff somewhere due to limitations on Django's generic interfaces
    files = GenericRelation(
        to='ObservedFile',
        content_type_field='_storage_content_type',
        object_id_field='_storage_object_id'
    )
    parquet_partitions = GenericRelation(
        to='ParquetPartition',
        content_type_field='_storage_content_type',
        object_id_field='_storage_object_id'
    )
    arbitrary_files = GenericRelation(
        to='ArbitraryFile',
        content_type_field='_storage_content_type',
        object_id_field='_storage_object_id'
    )

    def get_bytes_used(self, instance = None) -> int:
        """
        Estimate storage used by summing the size of each file using the storage.

        Args:
            - [instance]: the instance that is being written to or read from storage
        """
        total = 0
        for file in self.files.all():
            try:
                if file != instance:
                    total += file.png.size
            except (FileNotFoundError, ValueError):
                pass
        for partition in self.parquet_partitions.all():
            try:
                if partition != instance:
                    total += partition.parquet_file.size
            except (FileNotFoundError, ValueError):
                pass
        for af in self.arbitrary_files.all():
            try:
                if af != instance:
                    total += af.file.size
            except (FileNotFoundError, ValueError):
                pass
        return total

    def get_storage(self, instance, adding=False) -> Storage:
        """
        Return a *Storage() instance.

        Args:
            - instance: the thing that is being written to or read from storage
            - adding: whether the storage will be used for adding (True) or reading (False)

        Raises:
            - StorageConfigurationError if the storage is misconfigured
            - StorageFullError if the storage is full and adding=True
        """
        raise StorageConfigurationError("Subclasses must implement this method") from NotImplementedError

    @staticmethod
    def has_create_permission(request):
        return get_user_auth_details(request).is_lab_admin

    @staticmethod
    def has_read_permission(_):
        return True

    @staticmethod
    def has_write_permission(_):
        return True

    def has_object_read_permission(self, request):
        return self.lab.has_object_read_permission(request)

    def has_object_write_permission(self, request):
        return self.lab.has_object_write_permission(request)

    def __str__(self):
        if self.name is None:
            return f"{self.__class__.__name__} for {self.lab.name}"
        return f"{self.name} [{self.__class__.__name__}]"

    class Meta:
        unique_together = [['lab', 'priority']]
        abstract = True


class GalvStorageType(_StorageType):
    """
    GalvStorageType is storage that the Galv server provides to Labs.
    This has a quota set by the LAB_STORAGE_QUOTA_BYTES setting.

    It _must not_ be updatable by Lab admins because it is a system resource.

    Galv systems may offer GalvStorageType as a LocalStorage (i.e. stored on the server's filesystem),
    or as an S3DataStorage (i.e. stored in an S3 bucket that the Galv host pays for).

    If LAB_STORAGE_QUOTA_BYTES is set to 0, then GalvStorageType is disabled.
    """
    @property
    def location(self):
        return os.path.join(settings.DATA_ROOT, f"lab_{self.lab.pk}")

    @property
    def base_url(self):
        return os.path.join(settings.DATA_URL, f"lab_{self.lab.pk}")

    def get_storage(self, instance, adding=False) -> Storage:
        # We can only detect whether a file is being added.
        # Theoretically, this means that locked storage could be consumed where
        # a file was uploaded to unlocked storage and then edited once storage was locked.
        # This also means that storage quotas are not enforced for file edits.
        # To avoid this issue, we ensure that all consumers of the storage type
        # disallow editing of files.
        # ParquetPartitions are never edited - if they change they are destroyed and recreated
        # PNG previews for ObservedFiles have a hard limit on size in the settings
        # ArbitraryFiles cannot be edited, only created or deleted
        if adding:
            if not self.enabled:
                raise StorageLockedError(f"Cannot save data: storage is locked for {self}")
            if self.get_bytes_used(instance) + instance.bytes_required >= self.quota:
                raise StorageFullError(f"Cannot save data: local storage quota exceeded for {self}")
        try:
            if settings.S3_ENABLED and settings.LABS_USE_OUR_S3_STORAGE:
                return S3DataStorage(
                    access_key=settings.AWS_ACCESS_KEY_ID,
                    secret_key=settings.AWS_SECRET_ACCESS_KEY,
                    bucket_name=settings.AWS_STORAGE_BUCKET_NAME,
                    region_name=settings.AWS_S3_REGION_NAME,
                    location=self.location,
                    custom_domain=settings.AWS_S3_CUSTOM_DOMAIN
                )
            return LocalDataStorage(location=self.location, base_url=self.base_url)
        except Exception as e:
            raise StorageConfigurationError(f"Could not configure storage for {self}") from e

    @staticmethod
    def has_create_permission(_):
        return False


class AdditionalS3StorageType(_StorageType):
    """
    AdditionalS3StorageType is storage that the Lab can use for its own purposes.
    This has a quota set by the Lab admin.

    AdditionalS3StorageType is always an S3DataStorage (i.e. stored in an S3 bucket that the Lab pays for).

    In future, we may offer other storage options with other cloud providers or linking in with
    the lab's own storage solutions.
    """
    bucket_name = models.TextField(null=True, blank=True, help_text="Name of the S3 bucket to store files in")
    location = models.TextField(null=True, blank=True, help_text="Directory within the S3 bucket to store files in")
    access_key = models.TextField(null=True, blank=True, help_text="Access key for the S3 bucket")
    secret_key = models.TextField(null=True, blank=True, help_text="Secret key for the S3 bucket")
    region_name = models.TextField(
        blank=True,
        help_text="Region for the S3 bucket. Only one of custom domain or region should be set.",
        default="eu-west-2"
    )
    custom_domain = models.TextField(
        null=True,
        blank=True,
        help_text=("Custom domain for the S3 bucket.")
    )

    def get_storage(self, instance, adding=False) -> Storage:
        if adding:
            if not self.enabled:
                raise StorageLockedError(f"Cannot save data: storage is locked for {self}")
            if self.get_bytes_used(instance) + instance.bytes_required >= self.quota:
                raise StorageFullError(f"Cannot save data: storage quota exceeded for {self}")
        try:
            return S3DataStorage(
                access_key=self.access_key,
                secret_key=self.secret_key,
                bucket_name=self.bucket_name,
                region_name=self.region_name,
                location=self.location,
                custom_domain=self.custom_domain
            )
        except Exception as e:
            raise StorageConfigurationError(f"Could not configure storage for {self}") from e

    def has_object_write_permission(self, request):
        return self.lab.has_object_write_permission(request)

    def has_object_read_permission(self, request):
        return self.lab.has_object_read_permission(request)


class Lab(TimestampedModel):
    name = models.TextField(
        unique=True,
        help_text="Human-friendly Lab identifier"
    )
    description = models.TextField(
        null=True,
        help_text="Description of the Lab"
    )

    admin_group = models.OneToOneField(
        to=GroupProxy,
        on_delete=models.CASCADE,
        null=True,
        related_name='editable_lab',
        help_text="Users authorised to make changes to the Lab"
    )

    @staticmethod
    def has_read_permission(_):
        return True

    @staticmethod
    def has_write_permission(_):
        return True

    @staticmethod
    def has_create_permission(request):
        return get_user_auth_details(request).is_authenticated

    def has_object_read_permission(self, request):
        return request.user.is_staff or \
            request.user.is_superuser or \
            self.pk in get_user_auth_details(request).lab_ids

    def has_object_write_permission(self, request):
        return request.user.is_staff or \
            request.user.is_superuser or \
            self.pk in get_user_auth_details(request).writeable_lab_ids

    def __str__(self):
        return f"{self.name} [Lab {self.pk}]"

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        super(Lab, self).save(force_insert, force_update, using, update_fields)
        if self.admin_group is None:
            # Create groups for Lab
            self.admin_group = GroupProxy.objects.create(name=f"Lab {self.pk} admins")
            self.save()

    def delete(self, using=None, keep_parents=False):
        self.admin_group.delete()
        super(Lab, self).delete(using, keep_parents)

    def get_all_storage_types(self) -> list[_StorageType]:
        """
        Return a list of all storage types available to this Lab, sorted by priority (highest first).
        """
        storage_types = []
        for model in _StorageType.__subclasses__():
            storage_types.extend(list(model.objects.filter(lab=self)))
        return sorted(storage_types, key=lambda x: x.priority, reverse=True)

    def get_storage(self, instance, saving=False):
        if instance.storage_type is not None:
            return instance.storage_type.get_storage(instance, saving)

        storage_types = self.get_all_storage_types()
        if len(storage_types) == 0:
            raise StorageError(f"No storage available for {self}")

        errors = {}
        # Select the highest priority storage that works
        for storage_type in storage_types:
            try:
                storage_instance = storage_type.get_storage(instance, saving)
                instance.storage_type = storage_type
                # instance.save()  # this was double-adding the instance on create leading to duplicate id errors
                return storage_instance
            except StorageError as e:
                errors[storage_type] = e
        results = '\n'.join([f"{k}: {v}" for k, v in errors.items()])
        raise StorageError(f"No storage available. Errors:\n{results}.")


class Team(TimestampedModel):
    name = models.TextField(
        unique=False,
        help_text="Human-friendly Team identifier"
    )
    description = models.TextField(
        null=True,
        help_text="Description of the Team"
    )
    lab = models.ForeignKey(
        to=Lab,
        on_delete=models.CASCADE,
        null=False,
        related_name='teams',
        help_text="Lab to which this Team belongs"
    )
    admin_group = models.OneToOneField(
        to=GroupProxy,
        on_delete=models.CASCADE,
        null=True,
        related_name='editable_team',
        help_text="Users authorised to make changes to the Team"
    )
    member_group = models.OneToOneField(
        to=GroupProxy,
        on_delete=models.CASCADE,
        null=True,
        related_name='readable_team',
        help_text="Users authorised to view this Team's Experiments"
    )

    @staticmethod
    def has_create_permission(request):
        return get_user_auth_details(request).is_lab_admin

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return True

    def has_object_read_permission(self, request):
        return self.lab.pk in get_user_auth_details(request).writeable_lab_ids or \
            self.pk in get_user_auth_details(request).team_ids

    def has_object_write_permission(self, request):
        return self.lab.pk in get_user_auth_details(request).writeable_lab_ids or \
            self.pk in get_user_auth_details(request).writeable_team_ids

    def __str__(self):
        return f"{self.name} [Team {self.pk}]"

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        super(Team, self).save(force_insert, force_update, using, update_fields)
        if self.admin_group is None or self.member_group is None:
            if self.admin_group is None:
                # Create groups for Team
                self.admin_group = GroupProxy.objects.create(name=f"Team {self.pk} admins")
            if self.member_group is None:
                self.member_group = GroupProxy.objects.create(name=f"Team {self.pk} members")
            self.save()


    def delete(self, using=None, keep_parents=False):
        self.admin_group.delete()
        self.member_group.delete()
        super(Team, self).delete(using, keep_parents)

    class Meta:
        unique_together = [['name', 'lab']]


class ResourceModelPermissionsMixin(TimestampedModel):
    team = models.ForeignKey(
        to=Team,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(class)s_resources"
    )
    delete_access_level = models.IntegerField(
        default=UserLevel.TEAM_MEMBER.value,
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_DELETE]
    )
    edit_access_level = models.IntegerField(
        default=UserLevel.TEAM_MEMBER.value,
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_EDIT]
    )
    read_access_level = models.IntegerField(
        default=UserLevel.LAB_MEMBER.value,
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_READ]
    )

    def get_user_level(self, request):
        if self.team:
            if self.team.pk in get_user_auth_details(request).writeable_team_ids:
                return UserLevel.TEAM_ADMIN.value
            if self.team.pk in get_user_auth_details(request).team_ids:
                return UserLevel.TEAM_MEMBER.value
            if self.team.lab.pk in get_user_auth_details(request).lab_ids:
                return UserLevel.LAB_MEMBER.value
        if get_user_auth_details(request).is_authenticated:
            return UserLevel.REGISTERED_USER.value
        return UserLevel.ANONYMOUS.value

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        """
        Ensure that access levels are valid.
        Read <= Edit <= Delete
        """
        if self.read_access_level > self.edit_access_level:
            self.read_access_level = self.edit_access_level
        if self.edit_access_level > self.delete_access_level:
            self.edit_access_level = self.delete_access_level
        super(ResourceModelPermissionsMixin, self).save(force_insert, force_update, using, update_fields)


    def has_object_read_permission(self, request):
        return self.get_user_level(request) >= self.read_access_level

    def has_object_write_permission(self, request):
        return self.get_user_level(request) >= self.edit_access_level

    def has_object_destroy_permission(self, request):
        return self.get_user_level(request) >= self.delete_access_level

    @staticmethod
    def has_create_permission(request):
        """
        Users must be in a team to create a resource
        """
        return len(get_user_auth_details(request).team_ids) > 0

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return True

    class Meta:
        abstract = True


class ValidatableBySchemaMixin(TimestampedModel):
    """
    Subclasses are picked up by a crawl in ValidationSchemaViewSet and used
    to list possible values for validation schema root keys.
    """
    def register_validation(self):
        for schema in ValidationSchema.objects.all():
            SchemaValidation.objects.update_or_create(
                defaults={
                    "status": ValidationStatus.UNCHECKED,
                    "detail": None
                },
                schema=schema,
                content_type=ContentType.objects.get_for_model(self),
                object_id=self.pk
            )

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        super(ValidatableBySchemaMixin, self).save(force_insert, force_update, using, update_fields)
        # TODO: stop this happening for minor updates to Files, e.g. when last checked time is updated
        self.register_validation()

    class Meta:
        abstract = True


class BibliographicInfo(TimestampedModel):
    user = models.OneToOneField(to=UserProxy, on_delete=models.CASCADE, null=False, blank=False)
    bibjson = models.JSONField(null=False, blank=False)

    def has_object_read_permission(self, request):
        return self.user == request.user

    def has_object_write_permission(self, request):
        return self.user == request.user

    @staticmethod
    def has_create_permission(request):
        return get_user_auth_details(request).is_authenticated and get_user_auth_details(request).is_approved

    @staticmethod
    def has_read_permission(request):
        return UserProxy.has_read_permission(request)

    def __str__(self):
        return f"{self.user.username} byline"


class CellFamily(CustomPropertiesModel, ResourceModelPermissionsMixin):
    manufacturer = models.ForeignKey(to=CellManufacturers, help_text="Name of the manufacturer", null=True, blank=True, on_delete=models.CASCADE)
    model = models.ForeignKey(to=CellModels, help_text="Model number for the cells", null=False, on_delete=models.CASCADE)
    chemistry = models.ForeignKey(to=CellChemistries, help_text="Chemistry of the cells", null=True, blank=True, on_delete=models.CASCADE)
    form_factor = models.ForeignKey(to=CellFormFactors, help_text="Physical shape of the cells", null=True, blank=True, on_delete=models.CASCADE)
    datasheet = models.URLField(help_text="Link to the datasheet", null=True, blank=True)
    nominal_voltage = models.FloatField(help_text="Nominal voltage of the cells (in volts)", null=True, blank=True)
    nominal_capacity = models.FloatField(help_text="Nominal capacity of the cells (in amp hours)", null=True, blank=True)
    initial_ac_impedance = models.FloatField(help_text="Initial AC impedance of the cells (in ohms)", null=True, blank=True)
    initial_dc_resistance = models.FloatField(help_text="Initial DC resistance of the cells (in ohms)", null=True, blank=True)
    energy_density = models.FloatField(help_text="Energy density of the cells (in watt hours per kilogram)", null=True, blank=True)
    power_density = models.FloatField(help_text="Power density of the cells (in watts per kilogram)", null=True, blank=True)

    def in_use(self) -> bool:
        return self.cells.count() > 0

    def __str__(self):
        return f"{str(self.manufacturer)} {str(self.model)} ({str(self.chemistry)}, {str(self.form_factor)})"

    class Meta(CustomPropertiesModel.Meta):
        unique_together = [['model', 'manufacturer']]

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        super(CellFamily, self).save(force_insert, force_update, using, update_fields)

class Cell(JSONModel, ResourceModelPermissionsMixin, ValidatableBySchemaMixin):
    identifier = models.TextField(unique=False, help_text="Unique identifier (e.g. serial number) for the cell", null=False)
    family = models.ForeignKey(to=CellFamily, on_delete=models.CASCADE, null=False, help_text="Cell type", related_name="cells")

    def in_use(self) -> bool:
        return self.cycler_tests.count() > 0

    def __str__(self):
        return f"{self.identifier} [{str(self.family)}]"

    def __json_ld__(self):
        return combine_rdf_props(
            super().__json_ld__(),
            {
                "_context": [LDSources.BattINFO, LDSources.SCHEMA],
                "@type": f"{LDSources.BattINFO}:BatteryCell",
                f"{LDSources.SCHEMA}:serialNumber": self.identifier,
                f"{LDSources.SCHEMA}:identifier": self.family.model.__json_ld__(),
                f"{LDSources.SCHEMA}:documentation": str(self.family.datasheet),
                f"{LDSources.SCHEMA}:manufacturer": self.family.manufacturer.__json_ld__()
                # TODO: Add more fields from CellFamily
            }
        )

    class Meta(JSONModel.Meta):
        unique_together = [['identifier', 'family']]


class EquipmentFamily(CustomPropertiesModel, ResourceModelPermissionsMixin):
    type = models.ForeignKey(to=EquipmentTypes, on_delete=models.CASCADE, null=False, help_text="Type of equipment")
    manufacturer = models.ForeignKey(to=EquipmentManufacturers, on_delete=models.CASCADE, null=False, help_text="Manufacturer of equipment")
    model = models.ForeignKey(to=EquipmentModels, on_delete=models.CASCADE, null=False, help_text="Model of equipment")

    def in_use(self) -> bool:
        return self.equipment.count() > 0

    def __str__(self):
        return f"{str(self.manufacturer)} {str(self.model)} ({str(self.type)})"

class Equipment(JSONModel, ResourceModelPermissionsMixin, ValidatableBySchemaMixin):
    identifier = models.TextField(unique=True, help_text="Unique identifier (e.g. serial number) for the equipment", null=False)
    family = models.ForeignKey(to=EquipmentFamily, on_delete=models.CASCADE, null=False, help_text="Equipment type", related_name="equipment")
    calibration_date = models.DateField(help_text="Date of last calibration", null=True, blank=True)

    def in_use(self) -> bool:
        return self.cycler_tests.count() > 0

    def __str__(self):
        return f"{self.identifier} [{str(self.family)}]"

    def __json_ld__(self):
        return {
            "_context": [LDSources.BattINFO, LDSources.SCHEMA],
            "@type": self.family.type.__json_ld__(),
            f"{LDSources.SCHEMA}:serialNumber": self.identifier,
            f"{LDSources.SCHEMA}:identifier": str(self.family.model.__json_ld__()),
            f"{LDSources.SCHEMA}:manufacturer": str(self.family.manufacturer.__json_ld__())
        }


class ScheduleFamily(CustomPropertiesModel, ResourceModelPermissionsMixin):
    identifier = models.OneToOneField(to=ScheduleIdentifiers, unique=True, blank=False, null=False, help_text="Type of experiment, e.g. Constant-Current Discharge", on_delete=models.CASCADE)
    description = models.TextField(help_text="Description of the schedule")
    ambient_temperature = models.FloatField(help_text="Ambient temperature during the experiment (in degrees Celsius)", null=True, blank=True)
    pybamm_template = ArrayField(base_field=models.TextField(), help_text="Template for the schedule in PyBaMM format", null=True, blank=True)

    def pybamm_template_variable_names(self):
        template = "\n".join(self.pybamm_template)
        return re.findall(r"\{([\w_]+)}", template)

    def in_use(self) -> bool:
        return self.schedules.count() > 0

    def __str__(self):
        return f"{str(self.identifier)}"


class Schedule(JSONModel, ResourceModelPermissionsMixin, ValidatableBySchemaMixin):
    family = models.ForeignKey(to=ScheduleFamily, on_delete=models.CASCADE, null=False, help_text="Schedule type", related_name="schedules")
    schedule_file = models.FileField(help_text="File containing the schedule", null=True, blank=True)
    pybamm_schedule_variables = models.JSONField(help_text="Variables used in the PyBaMM.Experiment representation of the schedule", null=True, blank=True)

    def in_use(self) -> bool:
        return self.cycler_tests.count() > 0

    def __str__(self):
        return f"{str(self.id)} [{str(self.family)}]"

class Harvester(UUIDModel):
    name = models.TextField(
        help_text="Human-friendly Harvester identifier"
    )
    api_key = models.TextField(
        null=True,
        help_text="API access token for the Harvester"
    )
    last_check_in = models.DateTimeField(
        null=True,
        help_text="Date and time of last Harvester contact"
    )
    last_check_in_job = models.TextField(
        null=True,
        help_text="Job description of last Harvester contact"
    )
    sleep_time = models.IntegerField(
        default=120,
        help_text="Seconds to sleep between Harvester cycles"
    )  # default to short time so updates happen quickly
    active = models.BooleanField(
        default=True,
        help_text="Whether the Harvester is active"
    )
    lab = models.ForeignKey(
        to=Lab,
        on_delete=models.CASCADE,
        related_name="harvesters",
        null=False,
        help_text="Lab to which this Harvester belongs"
    )

    class Meta:
        unique_together = [['name', 'lab']]

    @staticmethod
    def has_create_permission(request):
        return get_user_auth_details(request).is_authenticated and len(get_user_auth_details(request).writeable_lab_ids) > 0

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return True

    def has_object_read_permission(self, request):
        return self.is_valid_harvester(request) or self.lab.has_object_read_permission(request)

    def has_object_write_permission(self, request):
        return self.lab.has_object_write_permission(request)

    def is_valid_harvester(self, request):
        return isinstance(request.user, HarvesterUser) and request.user.harvester == self

    def has_object_config_permission(self, request):
        return self.is_valid_harvester(request)

    def has_object_report_permission(self, request):
        return self.is_valid_harvester(request)

    def __str__(self):
        return f"{self.name} [Harvester {self.id}]"

    def save(self, *args, **kwargs):
        if self.api_key is None:
            # Create groups for Harvester
            text = 'abcdefghijklmnopqrstuvwxyz' + \
                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + \
                   '0123456789' + \
                   '!£$%^&*-=+'
            self.api_key = f"galv_hrv_{''.join(random.choices(text, k=60))}"
        super(Harvester, self).save(*args, **kwargs)


class ColumnMapping(UUIDModel, ResourceModelPermissionsMixin):
    """
    A mapping of DataColumn names to DataColumnType names.
    Mapping has the structure:
    {
        "column_name_in_file": {
            "column_type": "DataColumnType_id",
            "new_name": "New name for the column",
            "multiplier": 1.0,
            "addition": 1.0
        }
    }
    """
    name = models.TextField(unique=True)
    map = models.JSONField(
        null=False,
        help_text=(
            "Mapping of column names to Column objects. "
            "Each key is a column name in the file, and each value is a dictionary with the following keys: "
            "`column_type` (required): the ID of the DataColumnType object to map to, "
            "`new_name` (optional): a new name for the column (defaults to column_type's name) "
            "and cannot be specified for required columns "
            "(recommended to use a lowercase style with units in square brackets e.g. `speed_increase[m.s-1]`), "
            "`multiplier` (optional): a multiplier to apply to the column, "
            "`addition` (optional): a value to add to the column. "
            "Multiplier and addition are only used for numerical (int/float) columns. "
            "The new value is calculated as `new_value = (old_value + addition) * multiplier`. "
            "Columns will be renamed to match the DataColumnType name. "
            "**Columns not in the map will be coerced to float datatype.**"
        )
    )

    @property
    def in_use(self) -> bool:
        return self.observed_files.count() > 0

    @property
    def missing_required_columns(self) -> list[str]:
        """
        Return a list of missing required columns.
        """
        ids = [col['column_type'] for col in self.map.values()]
        missing = []
        for col in DataColumnType.objects.filter(is_required=True):
            if col.pk not in ids:
                missing.append(col.name)
        return missing

    @property
    def is_valid(self) -> bool:
        """
        A valid mapping contains all required columns.
        """
        return len(self.missing_required_columns) == 0

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        try:
            old_self = ColumnMapping.objects.get(pk=self.pk)
        except ColumnMapping.DoesNotExist:
            old_self = None
        update_files = old_self is not None and self.pk and self.map != old_self.map
        super(ColumnMapping, self).save(force_insert, force_update, using, update_fields)
        if update_files:
            for file in self.observed_files.all():
                file.state = FileState.MAP_ASSIGNED
                file.save()

    def __str__(self):
        return self.name


class ObservedFile(_StorageTypeConsumerModel, ValidatableBySchemaMixin):
    path = models.TextField(help_text="Absolute file path")
    harvester = models.ForeignKey(
        to=Harvester,
        on_delete=models.CASCADE,
        help_text="Harvester that harvested the File"
    )
    last_observed_size = models.PositiveBigIntegerField(
        null=False,
        default=0,
        help_text="Size of the file as last reported by Harvester"
    )
    last_observed_time = models.DateTimeField(
        null=True,
        help_text="Date and time of last Harvester report on file"
    )
    state = models.TextField(
        choices=FileState.choices,
        default=FileState.UNSTABLE,
        null=False,
        help_text=f"File status; autogenerated but can be manually set to {FileState.RETRY_IMPORT}"
    )
    data_generation_date = models.DateTimeField(
        null=True,
        help_text="Date and time of generated data. Time will be midnight if not specified in raw data"
    )
    inferred_format = models.TextField(
        null=True,
        help_text="Format of the raw data"
    )
    name = models.TextField(
        null=True,
        help_text="Name of the file"
    )
    parser = models.TextField(
        null=True,
        help_text="Parser used by the harvester"
    )
    num_rows = models.PositiveIntegerField(
        null=True,
        help_text="Number of rows in the file"
    )
    num_partitions = models.PositiveIntegerField(
        null=True,
        help_text="Number of partitions in the file's parquet format"
    )
    first_sample_no = models.PositiveIntegerField(
        null=True,
        help_text="Number of the first sample in the file"
    )
    last_sample_no = models.PositiveIntegerField(
        null=True,
        help_text="Number of the last sample in the file"
    )
    core_metadata = models.JSONField(
        null=True,
        help_text="Unparsed core metadata from the harvester"
    )
    extra_metadata = models.JSONField(
        null=True,
        help_text="Extra metadata from the harvester"
    )
    monitored_paths = models.ManyToManyField(
        to='MonitoredPath',
        help_text="Paths that this file is on",
        related_name="files",
        blank=True
    )
    summary = models.JSONField(null=True, blank=True)
    mapping = models.ForeignKey(
        ColumnMapping,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="observed_files"
    )
    png = LabDependentStorageFileField(
        null=True,
        blank=True,
        help_text="Preview image of the file"
    )

    view_name = "observedfile-png"

    def _get_lab(self):
        return self.harvester.lab

    @property
    def has_required_columns(self) -> bool:
        """
        Return whether the file has all required columns.
        """
        if self.mapping is None:
            return False
        return self.mapping.is_valid

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return True

    def has_object_read_permission(self, request):
        if self.harvester.is_valid_harvester(request):
            return True
        return any([path.has_object_read_permission(request) for path in self.monitored_paths.all()])

    def has_object_write_permission(self, request):
        if self.harvester.is_valid_harvester(request):
            return True
        return any([path.has_object_write_permission(request) for path in self.monitored_paths.all()])

    def applicable_mappings(self, request):
        """
        Return a list of applicable mappings for this file,
        sorted by validity (whether the mapping has all key columns),
        and applicability (number of file columns missed).
        """
        if not isinstance(self.summary, dict):
            return []
        col_names = self.summary.keys()
        applicable_valid_mappings = []
        applicable_invalid_mappings = []
        for mapping in ColumnMapping.objects.all():
            mapping.has_object_read_permission(request)
            # A mapping is only applicable if all of its keys are in the column names
            if any([m not in col_names for m in mapping.map.keys()]):
                continue
            # Applicability is scored by the number of column names it matches
            matches = []
            for col in col_names:
                if col in mapping.map:
                    matches.append(col)
            missing = len(col_names) - len(matches)
            if mapping.is_valid:
                applicable_valid_mappings.append({'mapping': mapping, 'missing': missing})
            else:
                applicable_invalid_mappings.append({'mapping': mapping, 'missing': missing})

        applicable_valid_mappings = sorted(applicable_valid_mappings, key=lambda x: x['missing'])
        applicable_invalid_mappings = sorted(applicable_invalid_mappings, key=lambda x: x['missing'])
        return [*applicable_valid_mappings, *applicable_invalid_mappings]

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        # If the mapping is updated, set the state to MAP_ASSIGNED so the harvester reprocesses the data
        if self.pk:
            try:
                prev_mapping = ObservedFile.objects.get(pk=self.pk).mapping
            except ObservedFile.DoesNotExist:
                prev_mapping = None
            if prev_mapping != self.mapping:
                self.state = FileState.MAP_ASSIGNED if self.mapping else FileState.AWAITING_MAP_ASSIGNMENT
        super(ObservedFile, self).save(force_insert, force_update, using, update_fields)


    def __str__(self):
        return self.path

    class Meta(UUIDModel.Meta):
        unique_together = [['path', 'harvester']]


class CyclerTest(JSONModel, ResourceModelPermissionsMixin, ValidatableBySchemaMixin):
    cell = models.ForeignKey(to=Cell, on_delete=models.CASCADE, null=False, help_text="Cell that was tested", related_name="cycler_tests")
    schedule = models.ForeignKey(to=Schedule, null=True, blank=True, on_delete=models.CASCADE, help_text="Schedule used to test the cell", related_name="cycler_tests")
    equipment = models.ManyToManyField(to=Equipment, help_text="Equipment used to test the cell", related_name="cycler_tests")
    files = models.ManyToManyField(to=ObservedFile,  help_text="Test data", related_name="cycler_tests")

    def __str__(self):
        return f"{self.cell} [CyclerTest {self.id}]"

    def rendered_pybamm_schedule(self, validate = True):
        """
        Return the PyBaMM representation of the schedule, with variables filled in.
        Variables are taken from the cell properties, cell family properties, and schedule variables (most preferred first).
        """
        return render_pybamm_schedule(self.schedule, self.cell, validate = validate)


class Experiment(JSONModel, ResourceModelPermissionsMixin, ValidatableBySchemaMixin):
    title = models.TextField(help_text="Title of the experiment")
    description = models.TextField(help_text="Description of the experiment", null=True, blank=True)
    authors = models.ManyToManyField(to=UserProxy, help_text="Authors of the experiment")
    protocol = models.JSONField(help_text="Protocol of the experiment", null=True, blank=True)
    protocol_file = models.FileField(help_text="Protocol file of the experiment", null=True, blank=True)
    cycler_tests = models.ManyToManyField(to=CyclerTest, help_text="Cycler tests of the experiment", related_name="experiments")

    def __str__(self):
        return self.title


class HarvesterEnvVar(TimestampedModel):
    harvester = models.ForeignKey(
        to=Harvester,
        related_name='environment_variables',
        on_delete=models.CASCADE,
        null=False,
        help_text="Harvester whose environment this describes"
    )
    key = models.TextField(help_text="Name of the variable")
    value = models.TextField(help_text="Variable value")
    deleted = models.BooleanField(help_text="Whether this variable was deleted", default=False, null=False)

    def has_object_read_permission(self, request):
        return self.harvester.has_object_read_permission(request)

    def has_object_write_permission(self, request):
        return self.harvester.has_object_write_permission(request)

    @staticmethod
    def has_create_permission(request):
        return Harvester.has_write_permission(request)

    @staticmethod
    def has_read_permission(request):
        return Harvester.has_read_permission(request)

    @staticmethod
    def has_write_permission(request):
        return Harvester.has_write_permission(request)

    def __str__(self):
        return f"{self.key}={self.value}{'*' if self.deleted else ''}"

    class Meta:
        unique_together = [['harvester', 'key']]


class MonitoredPath(UUIDModel, ResourceModelPermissionsMixin):
    harvester = models.ForeignKey(
        to=Harvester,
        related_name='monitored_paths',
        on_delete=models.DO_NOTHING,
        null=False,
        help_text="Harvester with access to this directory"
    )
    path = models.TextField(help_text="Directory location on Harvester")
    regex = models.TextField(
        null=True,
        blank=True,
        help_text="""
    Python.re regular expression to filter files by, 
    applied to full file name starting from this Path's directory""",
        default=".*"
    )
    stable_time = models.PositiveSmallIntegerField(
        default=60,
        help_text="Number of seconds files must remain stable to be processed"
    )
    max_partition_line_count = models.PositiveIntegerField(
        default=100_000,
        help_text=(
            "Maximum number of lines per parquet partition. "
            "If your data are very wide, select a lower number. "
            "For data with < 50 columns or so, 100,000 is a good starting point."
        )
    )
    active = models.BooleanField(default=True, null=False)
    team = models.ForeignKey(
        to=Team,
        related_name='monitored_paths',
        on_delete=models.CASCADE,
        null=True,
        help_text="Team with access to this Path"
    )

    delete_access_level = models.IntegerField(
        default=UserLevel.TEAM_ADMIN.value,
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_DELETE]
    )
    edit_access_level = models.IntegerField(
        default=UserLevel.TEAM_ADMIN.value,
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_EDIT_PATH]
    )

    def __str__(self):
        return self.path

    @staticmethod
    def paths_match(parent: str, child: str, regex: str):
        if not child.startswith(parent):
            return False
        if regex is not None:
            return re.search(regex, os.path.relpath(child, parent)) is not None
        return True

    def matches(self, path):
        return self.paths_match(self.path, path, self.regex)

    class Meta(UUIDModel.Meta):
        unique_together = [['harvester', 'path', 'regex', 'team']]


class HarvestError(TimestampedModel):
    harvester = models.ForeignKey(
        to=Harvester,
        related_name='upload_errors',
        on_delete=models.CASCADE,
        help_text="Harvester which reported the error"
    )
    file = models.ForeignKey(
        to=ObservedFile,
        related_name='upload_errors',
        on_delete=models.SET_NULL,
        null=True,
        help_text="File where error originated"
    )
    error = models.TextField(help_text="Text of the error report")
    timestamp = models.DateTimeField(
        auto_now=True,
        null=True,
        help_text="Date and time error was logged in the database"
    )

    @staticmethod
    def has_create_permission(request):
        for harvester in Harvester.objects.all():
            if harvester.is_valid_harvester(request):
                return True
        return request.user.is_staff or request.user.is_superuser

    @staticmethod
    def has_read_permission(request):
        return Harvester.has_read_permission(request)

    def has_object_write_permission(self, request):
        return self.harvester.has_object_write_permission(request)

    def has_object_read_permission(self, request):
        return self.harvester.has_object_read_permission(request)

    def __str__(self):
        if self.file:
            return f"{self.error} [Harvester_{self.harvester_id}/{self.file}]"
        return f"{self.error} [Harvester_{self.harvester_id}]"


class DataUnit(ResourceModelPermissionsMixin):
    name = models.TextField(
        null=False,
        help_text="Common name"
    )
    symbol = models.TextField(
        null=False,
        help_text="Symbol"
    )
    description = models.TextField(help_text="What the Unit signifies, and how it is used")
    is_default = models.BooleanField(
        default=False,
        help_text="Whether the Unit is included in the initial list of Units"
    )

    @staticmethod
    def has_write_permission(request):
        return True

    @staticmethod
    def has_read_permission(request):
        return True

    def __str__(self):
        if self.symbol:
            return f"{self.symbol} | {self.name} - {self.description}"
        return f"{self.name} - {self.description}"


class DataColumnType(ResourceModelPermissionsMixin, ValidatableBySchemaMixin):
    unit = models.ForeignKey(
        to=DataUnit,
        on_delete=models.SET_NULL,
        null=True,
        help_text="Unit used for measuring the values in this column"
    )
    name = models.TextField(null=False, help_text="Human-friendly identifier")
    description = models.TextField(help_text="Origins and purpose")
    data_type = models.TextField(
        null=False,
        choices=[(v, v) for v in DATA_TYPES],
        help_text="Type of the data in this column",
        default="float"
    )
    is_default = models.BooleanField(
        default=False,
        help_text="Whether the Column is included in the initial list of known Column Types"
    )
    is_required = models.BooleanField(
        default=False,
        help_text="Whether the Column must be present in every Dataset"
    )
    override_child_name = models.TextField(
        null=True,
        blank=True,
        help_text="If set, this name will be used instead of the Column name in Dataframes"
    )

    @staticmethod
    def has_write_permission(request):
        return True

    @staticmethod
    def has_read_permission(request):
        return True

    def __str__(self):
        if self.is_default:
            if self.is_required:
                return f"{self.name} ({self.unit.symbol}) [required]"
            return f"{self.name} ({self.unit.symbol} [default])"
        return f"{self.name} ({self.unit.symbol})"

    class Meta:
        unique_together = [['unit', 'name']]


class TimeseriesRangeLabel(TimestampedModel):
    file = models.ForeignKey(
        to=ObservedFile,
        related_name='range_labels',
        null=False,
        on_delete=models.CASCADE,
        help_text="Dataset to which the Range applies"
    )
    label = models.TextField(
        null=False,
        help_text="Human-friendly identifier"
    )
    range_start = models.PositiveBigIntegerField(
        null=False,
        help_text="Row (sample number) at which the range starts"
    )
    range_end = models.PositiveBigIntegerField(
        null=False,
        help_text="Row (sample number) at which the range ends"
    )
    info = models.TextField(help_text="Additional information")

    def has_object_read_permission(self, request):
        return self.file.has_object_read_permission(request)

    def has_object_write_permission(self, request):
        return self.file.has_object_write_permission(request)

    def __str__(self) -> str:
        return f"{self.label} [{self.range_start}, {self.range_end}]: {self.info}"


class KnoxAuthToken(TimestampedModel):
    knox_token_key = models.TextField(help_text="KnoxToken reference ([token_key]_[user_id]")
    name = models.TextField(help_text="Convenient human-friendly name")

    def __str__(self):
        return f"{self.knox_token_key}:{self.name}"

    @staticmethod
    def has_create_permission(request):
        return request.user.is_active

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return False

    @staticmethod
    def has_destroy_permission(request):
        return True

    def has_object_read_permission(self, request):
        if not request.user.is_active:
            return False
        regex = re.search(f"_{request.user.id}$", self.knox_token_key)
        return not regex is None

    def has_object_destroy_permission(self, request):
        return self.has_object_read_permission(request)


class HarvesterUser(AnonymousUser):
    """
    Abstraction of a Harvester as a User.
    Used to link up Harvester API access through the Django authentification system.
    """
    harvester: Harvester = None

    def __init__(self, harvester: Harvester):
        super().__init__()
        self.harvester = harvester
        self.username = harvester.name

    def __str__(self):
        return "HarvesterUser"

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self.harvester.active


class ValidationSchema(CustomPropertiesModel, ResourceModelPermissionsMixin):
    """
    JSON schema that can be used for validating components.
    """
    name = models.TextField(null=False, help_text="Human-friendly identifier")
    schema = models.JSONField(help_text="JSON Schema")

    def save(
            self, force_insert=False, force_update=False, using=None, update_fields=None
    ):
        super(ValidationSchema, self).save(force_insert, force_update, using, update_fields)
        SchemaValidation.objects.filter(schema=self).update(status=ValidationStatus.UNCHECKED, detail=None)

    def __str__(self):
        return f"{self.name} [ValidationSchema {self.id}]"


class SchemaValidation(TimestampedModel):
    """
    Whether a component is valid according to a ValidationSchema.
    """
    schema = models.ForeignKey(to=ValidationSchema, on_delete=models.CASCADE, null=False,
                               help_text="ValidationSchema used to validate the component")
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.CharField(max_length=36)
    validation_target = GenericForeignKey("content_type", "object_id")
    status = models.TextField(null=False, help_text="Validation status", choices=ValidationStatus.choices)
    detail = models.JSONField(null=True, help_text="Validation detail")
    last_update = models.DateTimeField(auto_now=True, null=False, help_text="Date and time of last status update")

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return False

    def has_object_read_permission(self, request):
        return self.schema.has_object_read_permission(request)

    def __str__(self):
        return f"{self.validation_target.__str__} vs {self.schema.__str__}: {self.status}"

    def validate(self, halt_on_error = False):
        """
        Validate the component against the schema.
        """
        try:
            # Get the object's serializer
            import galv.serializers as galv_serializers
            model_class = self.content_type.model_class()
            serializer = None
            for s in dir(galv_serializers):
                x = getattr(galv_serializers, s)
                try:
                    if issubclass(x, serializers.Serializer):
                        if hasattr(x, 'Meta') and hasattr(x.Meta, 'model'):
                            if x.Meta.model == model_class:
                                serializer = x
                                break
                except:
                    pass
            if serializer is None:
                self.status = ValidationStatus.ERROR
                self.detail = f"Could not find serializer for {model_class}"
                return

            # Serialize the object and validate against the schema
            mock_request = RequestFactory().get(VALIDATION_MOCK_ENDPOINT)
            mock_request.META['SERVER_NAME'] = settings.ALLOWED_HOSTS[0]
            mock_request.user = User.objects.filter(is_superuser=True).first()
            data = serializer(self.validation_target, context={'request': mock_request}).data
            d = data if isinstance(data, list) else [data]
            try:
                # Create the schema to validate against by asserting we have type classname
                s = self.schema.schema
                s['type'] = "array"
                s['items'] = {'$ref': f"#/$defs/{model_class.__name__}"}
                jsonschema.validate(d, s)
                self.status = ValidationStatus.VALID
                self.detail = None
            except jsonschema.exceptions.ValidationError as e:
                def unwrap_validationerror(err):
                    if isinstance(err, jsonschema.exceptions.ValidationError):
                        return {
                            'message': err.message,
                            'context': [unwrap_validationerror(c) for c in err.context],
                            'cause': err.cause,
                            'json_path': err.json_path,
                            'validator': err.validator,
                            'validator_value': err.validator_value
                        }
                    return err
                self.status = ValidationStatus.INVALID
                self.detail = unwrap_validationerror(e)
            except _WrappedReferencingError:
                self.status = ValidationStatus.SKIPPED

        except Exception as e:
            if halt_on_error:
                raise e
            self.status = ValidationStatus.ERROR
            self.detail = {'message': f"Error running validation: {e}"}

    class Meta:
        indexes = [
            models.Index(fields=["content_type", "object_id"]),
            models.Index(fields=["status"]),
            models.Index(fields=["schema"])
        ]


class ArbitraryFile(_StorageTypeConsumerModel, ResourceModelPermissionsMixin):
    file = LabDependentStorageFileField(
        null=True,
        blank=True,
        help_text="File"
    )
    name = models.TextField(help_text="The name of the file", null=False, blank=False)
    description = models.TextField(help_text="The description of the file", null=True, blank=True)

    view_name = "arbitraryfile-file"

    def _get_lab(self):
        return self.team.lab

    def delete(self, using=None, keep_parents=False):
        self.file.delete()
        super(ArbitraryFile, self).delete(using, keep_parents)

    def __str__(self):
        return self.name

    class Meta:
        unique_together = [['name', 'team'], ['file', 'team']]


class ParquetPartition(_StorageTypeConsumerModel):
    """
    A datafile partition in .parquet format.
    Part of an ObservedFile's source datafile.
    Either saved locally as a LocalParquetPartition, or saved in S3 as an S3ParquetPartition.
    """
    observed_file = models.ForeignKey(
        to=ObservedFile,
        on_delete=models.CASCADE,
        null=False,
        help_text="ObservedFile containing this partition",
        related_name="parquet_partitions"
    )
    parquet_file = LabDependentStorageFileField(
        null=True,
        blank=True,
        help_text="Parquet file"
    )
    partition_number = models.PositiveIntegerField(
        null=False,
        help_text="Partition number"
    )
    upload_errors = models.JSONField(
        null=False,
        default=list,
        help_text="Upload errors"
    )

    view_name = "parquetpartition-file"

    def _get_lab(self):
        return self.observed_file.harvester.lab

    @staticmethod
    def has_read_permission(request):
        return True

    @staticmethod
    def has_write_permission(request):
        return True

    @staticmethod
    def has_create_permission(request):
        return False

    def has_object_read_permission(self, request):
        return self.observed_file.has_object_read_permission(request)

    def has_object_write_permission(self, request):
        return self.observed_file.has_object_write_permission(request)

    @property
    def uploaded(self) -> bool:
        return self.parquet_file is not None
