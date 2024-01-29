# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
import os.path
import re

import jsonschema
from drf_spectacular.types import OpenApiTypes
from rest_framework.reverse import reverse
from drf_spectacular.utils import extend_schema_field, extend_schema_serializer, OpenApiExample
from rest_framework.exceptions import ValidationError
from rest_framework.status import HTTP_403_FORBIDDEN

from ..models import Harvester, \
    HarvesterEnvVar, \
    HarvestError, \
    MonitoredPath, \
    ObservedFile, \
    Cell, \
    Equipment, \
    DataUnit, \
    DataColumnType, \
    DataColumn, \
    TimeseriesRangeLabel, \
    KnoxAuthToken, CellFamily, EquipmentTypes, CellFormFactors, CellChemistries, CellModels, CellManufacturers, \
    EquipmentManufacturers, EquipmentModels, EquipmentFamily, Schedule, ScheduleIdentifiers, CyclerTest, \
    render_pybamm_schedule, ScheduleFamily, ValidationSchema, Experiment, Lab, Team, GroupProxy, UserProxy, user_labs, \
    user_teams, SchemaValidation, UserActivation, UserLevel, ALLOWED_USER_LEVELS_READ, ALLOWED_USER_LEVELS_EDIT, \
    ALLOWED_USER_LEVELS_DELETE, ALLOWED_USER_LEVELS_EDIT_PATH
from ..models.utils import ScheduleRenderError
from django.utils import timezone
from django.conf.global_settings import DATA_UPLOAD_MAX_MEMORY_SIZE
from rest_framework import serializers
from knox.models import AuthToken

from .utils import AdditionalPropertiesModelSerializer, GetOrCreateTextField, augment_extra_kwargs, url_help_text, \
    get_model_field, PermissionsMixin, TruncatedUserHyperlinkedRelatedIdField, \
    TruncatedGroupHyperlinkedRelatedIdField, TruncatedHyperlinkedRelatedIdField, \
    CreateOnlyMixin, ValidationPresentationMixin

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='User details',
        description='Full details are only available to the user themselves, or to superusers',
        value={
            "username": "admin",
            "email": "admin@galv.ox",
            "first_name": "Adam",
            "last_name": "Minotaur",
            "url": "http://localhost:8001/users/1/",
            "id": 1,
            "is_staff": True,
            "is_superuser": True,
            "groups": [
                "http://localhost:8001/groups/1/",
                "http://localhost:8001/groups/2/"
            ],
            "permissions": {
                "create": True,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class UserSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    current_password = serializers.CharField(
        write_only=True,
        allow_blank=True,
        required=False,
        style={'input_type': 'password'},
        help_text="Current password"
    )

    @staticmethod
    def validate_password(value):
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters")
        return value

    def validate(self, attrs):
        current_password = attrs.pop('current_password', None)
        if self.instance and not self.instance.check_password(current_password):
            raise ValidationError(f"Current password is incorrect")
        return attrs

    def create(self, validated_data):
        user = UserProxy.objects.create_user(**validated_data, is_active=False)
        activation = UserActivation.objects.create(user=user)
        activation.send_email(request=self.context['request'])
        return user

    def update(self, instance, validated_data):
        if 'password' in validated_data:
            instance.set_password(validated_data.pop('password'))
        return super().update(instance, validated_data)

    class Meta:
        model = UserProxy
        write_fields = ['username', 'email', 'first_name', 'last_name']
        write_only_fields = ['password', 'current_password']
        read_only_fields = ['url', 'id', 'is_staff', 'is_superuser', 'permissions']
        fields = [*write_fields, *read_only_fields, *write_only_fields]
        extra_kwargs = augment_extra_kwargs({
            'password': {'write_only': True, 'help_text': "Password (8 characters minimum)"},
        })


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Group details',
        description='Groups are used to manage permissions for a set of users',
        value=[
            "http://localhost:8001/users/1/"
        ],
        response_only=True, # signal that example only applies to responses
    ),
])
class TransparentGroupSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    users = TruncatedUserHyperlinkedRelatedIdField(
        UserSerializer,
        ['url', 'id', 'username', 'first_name', 'last_name', 'permissions'],
        view_name='userproxy-detail',
        queryset=UserProxy.objects.filter(is_active=True),
        read_only=False,
        source='user_set',
        many=True,
        help_text="Users in the group"
    )

    @staticmethod
    def validate_users(value):
        # Only active users can be added to groups
        return [u for u in value if u.is_active]

    def update(self, instance, validated_data):
        if 'user_set' in validated_data:
            # Check there will be at least one user left for lab admin groups
            if hasattr(instance, 'editable_lab'):
                if len(validated_data['user_set']) < 1:
                    raise ValidationError(f"Labs must always have at least one administrator")
            instance.user_set.set(validated_data.pop('user_set'))
        return instance

    def to_representation(self, instance) -> list[str]:
        ret = super().to_representation(instance)
        return ret['users']

    def to_internal_value(self, data):
        return super().to_internal_value({'users': data})

    class Meta:
        model = GroupProxy
        fields = ['users']

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Team details',
        description='Teams are groups of users assigned to a project. They can easily create and share resources.',
        value={
            "url": "http://localhost:8001/teams/1/",
            "id": 1,
            "member_group": {
                "id": 3,
                "url": "http://localhost:8001/groups/3/",
                "name": "example_team_members",
                "users": [],
                "permissions": {
                    "create": False,
                    "destroy": False,
                    "write": True,
                    "read": True
                }
            },
            "admin_group": {
                "id": 2,
                "url": "http://localhost:8001/groups/2/",
                "name": "example_team_admins",
                "users": [
                    "http://localhost:8001/users/1/"
                ],
                "permissions": {
                    "create": False,
                    "destroy": False,
                    "write": True,
                    "read": True
                }
            },
            "monitored_paths": [],
            "cellfamily_resources": [
                "http://localhost:8001/cell_families/42fc4c44-efbb-4457-a734-f68ee28de617/",
                "http://localhost:8001/cell_families/5d19c8d6-a976-423d-ab5d-a624a0606d30/"
            ],
            "cell_resources": [
                "http://localhost:8001/cells/6a3a910b-d42e-46f6-9604-6fb3c2f3d059/",
                "http://localhost:8001/cells/4281a89b-48ff-4f4a-bcd8-5fe427f87a81/"
            ],
            "equipmentfamily_resources": [
                "http://localhost:8001/equipment_families/947e1f7c-c5b9-47b8-a121-d1e519a7154c/",
                "http://localhost:8001/equipment_families/6ef7c3b4-cb3b-421f-b6bf-de1e1acfaae8/"
            ],
            "equipment_resources": [
                "http://localhost:8001/equipment/a7bd4c43-29c7-40f1-bcf7-a2924ed474c2/",
                "http://localhost:8001/equipment/31fd16ef-0667-4a31-9232-b5a649913227/",
                "http://localhost:8001/equipment/12039516-72bf-42b7-a687-cb210ca4a087/"
            ],
            "schedulefamily_resources": [
                "http://localhost:8001/schedule_families/e25f7c94-ca32-4f47-b95a-3b0e7ae4a47f/"
            ],
            "schedule_resources": [
                "http://localhost:8001/schedules/5a2d7da9-393c-44ee-827a-5d15133c48d6/",
                "http://localhost:8001/schedules/7771fc54-7209-4564-9ec7-e87855f7ee67/"
            ],
            "cyclertest_resources": [
                "http://localhost:8001/cycler_tests/2b7313c9-94c2-4276-a4ee-e9d58d8a641b/",
                "http://localhost:8001/cycler_tests/e5a1a806-ef9e-4da8-9dd4-caa6cb491af9/"
            ],
            "experiment_resources": [],
            "permissions": {
                "create": True,
                "write": True,
                "read": True
            },
            "name": "Example Team",
            "description": "This Team exists to demonstrate the system.",
            "lab": "http://localhost:8001/labs/1/"
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class TeamSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    member_group = TransparentGroupSerializer(required=False, help_text="Members of this Team")
    admin_group = TransparentGroupSerializer(required=False, help_text="Administrators of this Team")
    cellfamily_resources = TruncatedHyperlinkedRelatedIdField(
        'CellFamilySerializer',
        ['manufacturer', 'model', 'chemistry', 'form_factor'],
        'cellfamily-detail',
        read_only=True,
        many=True,
        help_text="Cell Families belonging to this Team"
    )
    cell_resources = TruncatedHyperlinkedRelatedIdField(
        'CellSerializer',
        ['identifier', 'family'],
        'cell-detail',
        read_only=True,
        many=True,
        help_text="Cells belonging to this Team"
    )
    equipmentfamily_resources = TruncatedHyperlinkedRelatedIdField(
        'EquipmentFamilySerializer',
        ['type', 'manufacturer', 'model'],
        'equipmentfamily-detail',
        read_only=True,
        many=True,
        help_text="Equipment Families belonging to this Team"
    )
    equipment_resources = TruncatedHyperlinkedRelatedIdField(
        'EquipmentSerializer',
        ['identifier', 'family'],
        'equipment-detail',
        read_only=True,
        many=True,
        help_text="Equipment belonging to this Team"
    )
    schedulefamily_resources = TruncatedHyperlinkedRelatedIdField(
        'ScheduleFamilySerializer',
        ['identifier', ],
        'schedulefamily-detail',
        read_only=True,
        many=True,
        help_text="Schedule Families belonging to this Team"
    )
    schedule_resources = TruncatedHyperlinkedRelatedIdField(
        'ScheduleSerializer',
        ['family', ],
        'schedule-detail',
        read_only=True,
        many=True,
        help_text="Schedules belonging to this Team"
    )
    cyclertest_resources = TruncatedHyperlinkedRelatedIdField(
        'CyclerTestSerializer',
        ['cell', 'equipment', 'schedule'],
        'cyclertest-detail',
        read_only=True,
        many=True,
        help_text="Cycler Tests belonging to this Team"
    )
    experiment_resources = TruncatedHyperlinkedRelatedIdField(
        'ExperimentSerializer',
        ['title'],
        'experiment-detail',
        read_only=True,
        many=True,
        help_text="Experiments belonging to this Team"
    )
    lab = TruncatedHyperlinkedRelatedIdField(
        'LabSerializer',
        ['name'],
        'lab-detail',
        queryset=Lab.objects.all(),
        help_text="Lab this Team belongs to"
    )

    def validate_lab(self, value):
        """
        Only lab admins can create teams in their lab
        """
        try:
            assert value in user_labs(self.context['request'].user, True)
        except:
            raise ValidationError("You may only create Teams in your own lab(s)")
        return value

    def update(self, instance, validated_data):
        """
        Pass group updates to the group serializer
        """
        if 'admin_group' in validated_data:
            admin_group = validated_data.pop('admin_group')
            TransparentGroupSerializer().update(instance.admin_group, admin_group)
        if 'member_group' in validated_data:
            member_group = validated_data.pop('member_group')
            TransparentGroupSerializer().update(instance.member_group, member_group)
        return super().update(instance, validated_data)

    class Meta:
        model = Team
        read_only_fields = [
            'url', 'id',
            'monitored_paths',
            'cellfamily_resources', 'cell_resources',
            'equipmentfamily_resources', 'equipment_resources',
            'schedulefamily_resources', 'schedule_resources',
            'cyclertest_resources', 'experiment_resources',
            'permissions'
        ]
        fields = [*read_only_fields, 'name', 'description', 'lab', 'member_group', 'admin_group']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Lab details',
        description='Labs are collections of teams, and are used to organise access to raw data.',
        value={
            "url": "http://localhost:8001/labs/1/",
            "id": 1,
            "name": "Example Lab",
            "description": "This Lab exists to demonstrate the system.",
            "admin_group": {
                "id": 1,
                "url": "http://localhost:8001/groups/1/",
                "name": "example_lab_admins",
                "users": [
                    "http://localhost:8001/users/1/"
                ],
                "permissions": {
                    "create": False,
                    "destroy": False,
                    "write": True,
                    "read": True
                }
            },
            "harvesters": [],
            "teams": [
                "http://localhost:8001/teams/1/"
            ],
            "permissions": {
                "create": True,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class LabSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    admin_group = TransparentGroupSerializer(help_text="Group of users who can edit this Lab")
    teams = TruncatedHyperlinkedRelatedIdField(
        'TeamSerializer',
        ['name', 'admin_group', 'member_group'],
        'team-detail',
        read_only=True,
        many=True,
        help_text="Teams in this Lab"
    )

    def update(self, instance, validated_data):
        """
        Pass group updates to the group serializer
        """
        if 'admin_group' in validated_data:
            admin_group = validated_data.pop('admin_group')
            TransparentGroupSerializer().update(instance.admin_group, admin_group)
        return super().update(instance, validated_data)

    class Meta:
        model = Lab
        fields = ['url', 'id', 'name', 'description', 'admin_group', 'harvesters', 'teams', 'permissions']
        read_only_fields = ['url', 'id', 'teams', 'admin_group', 'harvesters', 'permissions']

class WithTeamMixin(serializers.Serializer):
    team = TruncatedHyperlinkedRelatedIdField(
        'TeamSerializer',
        ['name'],
        'team-detail',
        queryset=Team.objects.all(),
        help_text="Team this resource belongs to"
    )
    read_access_level = serializers.ChoiceField(
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_READ],
        help_text="Minimum user level required to read this resource",
        allow_null=True,
        required=False
    )
    edit_access_level = serializers.ChoiceField(
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_EDIT],
        help_text="Minimum user level required to edit this resource",
        allow_null=True,
        required=False
    )
    delete_access_level = serializers.ChoiceField(
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_DELETE],
        help_text="Minimum user level required to create this resource",
        allow_null=True,
        required=False
    )

    def validate_team(self, value):
        """
        Only team members can create resources in their team.
        If a resource is being moved from one team to another, the user must be a member of both teams.
        """
        teams = user_teams(self.context['request'].user)
        try:
            assert value in teams
        except:
            raise ValidationError("You may only create resources in your own team(s)", code=HTTP_403_FORBIDDEN)
        if self.instance is not None:
            try:
                assert self.instance.team in teams
            except:
                raise ValidationError("You may only edit resources in your own team(s)")
        else:
            assert value is not None
        return value

    def validate_access_level(self, value, allowed_values):
        try:
            v = UserLevel(value)
        except ValueError:
            raise ValidationError((
                f"Invalid access level '{value}'. "
                f"Expected one of {[v.value for v in allowed_values]}"
            ))
        if self.instance is not None:
            try:
                assert v in allowed_values
            except:
                raise ValidationError((
                    f"Invalid read access level '{value}'. "
                    f"Expected one of {[v.value for v in allowed_values]}"
                ))
        return v.value

    def validate_read_access_level(self, value):
        return self.validate_access_level(value, ALLOWED_USER_LEVELS_READ)

    def validate_edit_access_level(self, value):
        return self.validate_access_level(value, ALLOWED_USER_LEVELS_EDIT)

    def validate_delete_access_level(self, value):
        return self.validate_access_level(value, ALLOWED_USER_LEVELS_DELETE)

    def validate(self, attrs):
        """
        Only team members can change read and edit access levels.
        Only team admins can change delete access levels.
        Ensure access levels follow the hierarchy:
        READ <= EDIT <= DELETE
        """
        if self.instance is not None:
            # Remove unchanged access levels.
            # The frontend will send all access levels, even if they haven't changed,
            # so this is a convenience to prevent access denial when submitting unchanged data.
            for level in ['read_access_level', 'edit_access_level', 'delete_access_level']:
                if level in attrs and getattr(self.instance, level) == attrs[level]:
                    del attrs[level]
            user_access_level = self.instance.get_user_level(self.context['request'].user)
            if 'read_access_level' in attrs or 'edit_access_level' in attrs:
                if user_access_level < UserLevel.TEAM_MEMBER.value:
                    raise ValidationError("You may only change access levels if you are a team member")
                for access_level in ['read_access_level', 'edit_access_level']:
                    if access_level in attrs:
                        if getattr(self.instance, access_level) > user_access_level:
                            raise ValidationError(f"You may not change {access_level} because your access level is too low")
            if 'delete_access_level' in attrs:
                if user_access_level < UserLevel.TEAM_ADMIN.value:
                    raise ValidationError("You may only change delete access levels if you are a team admin")
        if 'read_access_level' in attrs:
            edit_level = attrs.get(
                'edit_access_level',
                self.instance.edit_access_level if self.instance else UserLevel.TEAM_ADMIN.value
            )
            if attrs['read_access_level'] > edit_level:
                raise ValidationError("Read access level must be less than or equal to edit access level")
        if 'edit_access_level' in attrs:
            delete_level = attrs.get(
                'delete_access_level',
                self.instance.delete_access_level if self.instance else UserLevel.TEAM_ADMIN.value
            )
            if attrs['edit_access_level'] > delete_level:
                raise ValidationError("Edit access level must be less than or equal to delete access level")
        return attrs

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Cell details',
        description='Cells are the electrical energy storage devices used in cycler tests. They are grouped into families.',
        value={
            "url": "http://localhost:8001/cells/6a3a910b-d42e-46f6-9604-6fb3c2f3d059/",
            "uuid": "6a3a910b-d42e-46f6-9604-6fb3c2f3d059",
            "identifier": "sny-vtc-1234-xx94",
            "family": "http://localhost:8001/cell_families/42fc4c44-efbb-4457-a734-f68ee28de617/",
            "cycler_tests": [
                "http://localhost:8001/cycler_tests/2b7313c9-94c2-4276-a4ee-e9d58d8a641b/"
            ],
            "in_use": True,
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": True,
                "destroy": True,
                "write": True,
                "read": True
            },
            "additional-property": "resources can have arbitrary additional JSON-serializable properties"
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class CellSerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin, ValidationPresentationMixin):
    family = TruncatedHyperlinkedRelatedIdField(
        'CellFamilySerializer',
        ['manufacturer', 'model', 'chemistry', 'form_factor'],
        'cellfamily-detail',
        queryset=CellFamily.objects.all(),
        help_text="Cell Family this Cell belongs to"
    )
    cycler_tests = TruncatedHyperlinkedRelatedIdField(
        'CyclerTestSerializer',
        ['equipment', 'schedule'],
        'cyclertest-detail',
        read_only=True,
        many=True,
        help_text="Cycler Tests using this Cell"
    )

    class Meta:
        model = Cell
        fields = [
            'url', 'uuid', 'identifier', 'family', 'cycler_tests', 'in_use', 'team',
            'permissions', 'read_access_level', 'edit_access_level', 'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'cycler_tests', 'in_use', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Cell Family details',
        description='Cell Families group together properties shared by multiple Cells of the same make and model.',
        value={
            "url": "http://localhost:8001/cell_families/5d19c8d6-a976-423d-ab5d-a624a0606d30/",
            "uuid": "5d19c8d6-a976-423d-ab5d-a624a0606d30",
            "manufacturer": "LG",
            "model": "HG2",
            "datasheet": None,
            "chemistry": "NMC",
            "nominal_voltage": 3.6,
            "nominal_capacity": None,
            "initial_ac_impedance": None,
            "initial_dc_resistance": None,
            "energy_density": None,
            "power_density": None,
            "form_factor": "Cyclindrical",
            "cells": [
                "http://localhost:8001/cells/4281a89b-48ff-4f4a-bcd8-5fe427f87a81/"
            ],
            "in_use": True,
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": True,
                "destroy": True,
                "write": True,
                "read": True
            },
            "fast_charge_constant_current": 0.5,
            "fast_charge_constant_voltage": 4.2,
            "standard_discharge_constant_current": 1.0
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class CellFamilySerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin):
    manufacturer = GetOrCreateTextField(foreign_model=CellManufacturers, help_text="Manufacturer name")
    model = GetOrCreateTextField(foreign_model=CellModels, help_text="Model number")
    chemistry = GetOrCreateTextField(foreign_model=CellChemistries, help_text="Chemistry type")
    form_factor = GetOrCreateTextField(foreign_model=CellFormFactors, help_text="Physical form factor")
    cells = TruncatedHyperlinkedRelatedIdField(
        'CellSerializer',
        ['identifier'],
        'cell-detail',
        read_only=True,
        many=True,
        help_text="Cells belonging to this Cell Family"
    )

    class Meta:
        model = CellFamily
        fields = [
            'url',
            'uuid',
            'manufacturer',
            'model',
            'datasheet',
            'chemistry',
            'nominal_voltage',
            'nominal_capacity',
            'initial_ac_impedance',
            'initial_dc_resistance',
            'energy_density',
            'power_density',
            'form_factor',
            'cells',
            'in_use',
            'team',
            'permissions',
            'read_access_level',
            'edit_access_level',
            'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'cells', 'in_use', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Equipment Family details',
        description='Equipment Families group together properties shared by multiple pieces of Equipment of the same make and model.',
        value={
            "url": "http://localhost:8001/equipment_families/947e1f7c-c5b9-47b8-a121-d1e519a7154c/",
            "uuid": "947e1f7c-c5b9-47b8-a121-d1e519a7154c",
            "type": "Thermal Chamber",
            "manufacturer": "Binder",
            "model": "KB115",
            "in_use": True,
            "team": "http://localhost:8001/teams/1/",
            "equipment": [
                "http://localhost:8001/equipment/a7bd4c43-29c7-40f1-bcf7-a2924ed474c2/",
                "http://localhost:8001/equipment/31fd16ef-0667-4a31-9232-b5a649913227/"
            ],
            "permissions": {
                "create": True,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class EquipmentFamilySerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin):
    type = GetOrCreateTextField(foreign_model=EquipmentTypes, help_text="Equipment type")
    manufacturer = GetOrCreateTextField(foreign_model=EquipmentManufacturers, help_text="Manufacturer name")
    model = GetOrCreateTextField(foreign_model=EquipmentModels, help_text="Model number")
    equipment = TruncatedHyperlinkedRelatedIdField(
        'EquipmentSerializer',
        ['identifier'],
        'equipment-detail',
        read_only=True,
        many=True,
        help_text="Equipment belonging to this Equipment Family"
    )

    class Meta:
        model = EquipmentFamily
        fields = [
            'url',
            'uuid',
            'type',
            'manufacturer',
            'model',
            'in_use',
            'team',
            'equipment',
            'permissions',
            'read_access_level',
            'edit_access_level',
            'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'in_use', 'equipment', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Equipment details',
        description='Equipment is used to perform cycler tests. It includes cyclers themselves, as well as temperature chambers. It is grouped into families.',
        value={
            "url": "http://localhost:8001/equipment/a7bd4c43-29c7-40f1-bcf7-a2924ed474c2/",
            "uuid": "a7bd4c43-29c7-40f1-bcf7-a2924ed474c2",
            "identifier": "1234567890",
            "family": "http://localhost:8001/equipment_families/947e1f7c-c5b9-47b8-a121-d1e519a7154c/",
            "calibration_date": "2019-01-01",
            "in_use": True,
            "team": "http://localhost:8001/teams/1/",
            "cycler_tests": [
                "http://localhost:8001/cycler_tests/2b7313c9-94c2-4276-a4ee-e9d58d8a641b/"
            ],
            "permissions": {
                "create": True,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class EquipmentSerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin, ValidationPresentationMixin):
    family = TruncatedHyperlinkedRelatedIdField(
        'EquipmentFamilySerializer',
        ['type', 'manufacturer', 'model'],
        'equipmentfamily-detail',
        queryset=EquipmentFamily.objects.all(),
        help_text="Equipment Family this Equipment belongs to"
    )
    cycler_tests = TruncatedHyperlinkedRelatedIdField(
        'CyclerTestSerializer',
        ['cell', 'schedule'],
        'cyclertest-detail',
        read_only=True,
        many=True,
        help_text="Cycler Tests using this Equipment"
    )

    class Meta:
        model = Equipment
        fields = [
            'url', 'uuid', 'identifier', 'family', 'calibration_date', 'in_use', 'team', 'cycler_tests',
            'permissions', 'read_access_level', 'edit_access_level', 'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'datasets', 'in_use', 'cycler_tests', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Schedule Family details',
        description='Schedule Families group together properties shared by multiple Schedules.',
        value={
            "url": "http://localhost:8001/schedule_families/e25f7c94-ca32-4f47-b95a-3b0e7ae4a47f/",
            "uuid": "e25f7c94-ca32-4f47-b95a-3b0e7ae4a47f",
            "identifier": "Cell Conditioning",
            "description": "Each cell is cycled five times at 1C discharge and the standard charge. This test is completed at 25◦C.",
            "ambient_temperature": 25.0,
            "pybamm_template": [
                "Charge at 1 A until 4.1 V",
                "Discharge at {standard_discharge_constant_current} C for 10 hours or until 3.3 V",
                "Charge at 1 A until 4.1 V",
                "Discharge at {standard_discharge_constant_current} C for 10 hours or until 3.3 V",
                "Charge at 1 A until 4.1 V",
                "Discharge at C/1 for 10 hours or until 3.3 V",
                "Charge at {fast_charge_constant_current} until {fast_charge_constant_voltage} V",
                "Discharge at {standard_discharge_constant_current} C for 10 hours or until 3.3 V",
                "Charge at 1 A until 4.1 V",
                "Discharge at {standard_discharge_constant_current} C for 10 hours or until 3.3 V"
            ],
            "in_use": True,
            "team": "http://localhost:8001/teams/1/",
            "schedules": [
                "http://localhost:8001/schedules/5a2d7da9-393c-44ee-827a-5d15133c48d6/",
                "http://localhost:8001/schedules/7771fc54-7209-4564-9ec7-e87855f7ee67/"
            ],
            "permissions": {
                "create": True,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class ScheduleFamilySerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin):
    identifier = GetOrCreateTextField(foreign_model=ScheduleIdentifiers)
    schedules = TruncatedHyperlinkedRelatedIdField(
        'ScheduleSerializer',
        ['family'],
        'schedule-detail',
        read_only=True,
        many=True,
        help_text="Schedules belonging to this Schedule Family"
    )

    def validate_pybamm_template(self, value):
        # TODO: validate pybamm template against pybamm.step.string
        return value

    class Meta:
        model = ScheduleFamily
        fields = [
            'url', 'uuid', 'identifier', 'description',
            'ambient_temperature', 'pybamm_template',
            'in_use', 'team', 'schedules', 'permissions',
            'read_access_level', 'edit_access_level', 'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'in_use', 'schedules', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Schedule details',
        description='Schedules are used to define the current profile used in a cycler test. They are grouped into families.',
        value={
            "url": "http://localhost:8001/schedules/5a2d7da9-393c-44ee-827a-5d15133c48d6/",
            "uuid": "5a2d7da9-393c-44ee-827a-5d15133c48d6",
            "family": "http://localhost:8001/schedule_families/e25f7c94-ca32-4f47-b95a-3b0e7ae4a47f/",
            "schedule_file": None,
            "pybamm_schedule_variables": {
                "fast_charge_constant_current": 1.0,
                "fast_charge_constant_voltage": 4.1,
                "standard_discharge_constant_current": 1.0
            },
            "in_use": True,
            "team": "http://localhost:8001/teams/1/",
            "cycler_tests": [
                "http://localhost:8001/cycler_tests/2b7313c9-94c2-4276-a4ee-e9d58d8a641b/"
            ],
            "permissions": {
                "create": True,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class ScheduleSerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin, ValidationPresentationMixin):
    family = TruncatedHyperlinkedRelatedIdField(
        'ScheduleFamilySerializer',
        ['identifier'],
        'schedulefamily-detail',
        queryset=ScheduleFamily.objects.all(),
        help_text="Schedule Family this Schedule belongs to"
    )
    cycler_tests = TruncatedHyperlinkedRelatedIdField(
        'CyclerTestSerializer',
        ['cell', 'equipment'],
        'cyclertest-detail',
        read_only=True,
        many=True,
        help_text="Cycler Tests using this Schedule"
    )

    def validate_pybamm_schedule_variables(self, value):
        template = self.instance.family.pybamm_template
        if template is None and value is not None:
            raise ValidationError("pybamm_schedule_variables has no effect if pybamm_template is not set")
        if value is None:
            return value
        keys = self.instance.family.pybamm_template_variable_names()
        for k, v in value.items():
            if k not in keys:
                raise ValidationError(f"Schedule variable {k} is not in the template")
            try:
                float(v)
            except (ValueError, TypeError):
                raise ValidationError(f"Schedule variable {k} must be a number")
        return value

    def validate(self, data):
        if data.get('schedule_file') is None:
            try:
                family = data.get('family') or self.instance.family
                assert family.pybamm_template is not None
            except (AttributeError, AssertionError):
                raise ValidationError("Schedule_file must be provided where pybamm_template is not set")
        return data

    class Meta:
        model = Schedule
        fields = [
            'url', 'uuid', 'family',
            'schedule_file', 'pybamm_schedule_variables',
            'in_use', 'team', 'cycler_tests', 'permissions',
            'read_access_level', 'edit_access_level', 'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'in_use', 'cycler_tests', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Cycler Test details',
        description='Cycler Tests are the core of the system. They define the cell, equipment, and schedule used in a test, and are used to store the raw data produced by the test.',
        value={
            "url": "http://localhost:8001/cycler_tests/2b7313c9-94c2-4276-a4ee-e9d58d8a641b/",
            "uuid": "2b7313c9-94c2-4276-a4ee-e9d58d8a641b",
            "cell": "http://localhost:8001/cells/6a3a910b-d42e-46f6-9604-6fb3c2f3d059/",
            "equipment": [
                "http://localhost:8001/equipment/a7bd4c43-29c7-40f1-bcf7-a2924ed474c2/",
                "http://localhost:8001/equipment/12039516-72bf-42b7-a687-cb210ca4a087/"
            ],
            "schedule": "http://localhost:8001/schedules/5a2d7da9-393c-44ee-827a-5d15133c48d6/",
            "rendered_schedule": [
                "Charge at 1 A until 4.1 V",
                "Discharge at 1 C for 10 hours or until 3.3 V",
                "Charge at 1 A until 4.1 V",
                "Discharge at 1 C for 10 hours or until 3.3 V",
                "Charge at 1 A until 4.1 V",
                "Discharge at C/1 for 10 hours or until 3.3 V",
                "Charge at 1.0 until 4.1 V",
                "Discharge at 1 C for 10 hours or until 3.3 V",
                "Charge at 1 A until 4.1 V",
                "Discharge at 1 C for 10 hours or until 3.3 V"
            ],
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": True,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class CyclerTestSerializer(AdditionalPropertiesModelSerializer, PermissionsMixin, WithTeamMixin):
    rendered_schedule = serializers.SerializerMethodField(help_text="Rendered schedule")
    schedule = TruncatedHyperlinkedRelatedIdField(
        'ScheduleSerializer',
        ['family'],
        'schedule-detail',
        queryset=Schedule.objects.all(),
        help_text="Schedule this Cycler Test uses"
    )
    cell = TruncatedHyperlinkedRelatedIdField(
        'CellSerializer',
        ['identifier', 'family'],
        'cell-detail',
        queryset=Cell.objects.all(),
        help_text="Cell this Cycler Test uses"
    )
    equipment = TruncatedHyperlinkedRelatedIdField(
        'EquipmentSerializer',
        ['identifier', 'family'],
        'equipment-detail',
        queryset=Equipment.objects.all(),
        many=True,
        help_text="Equipment this Cycler Test uses"
    )

    def get_rendered_schedule(self, instance) -> list[str] | None:
        if instance.schedule is None:
            return None
        return instance.rendered_pybamm_schedule(False)

    def validate(self, data):
        if data.get('schedule') is not None:
            try:
                render_pybamm_schedule(data['schedule'], data['cell'])
            except ScheduleRenderError as e:
                raise ValidationError(e)
        return data

    class Meta:
        model = CyclerTest
        fields = [
            'url', 'uuid', 'cell', 'equipment', 'schedule', 'rendered_schedule', 'team', 'permissions',
            'read_access_level', 'edit_access_level', 'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'rendered_schedule', 'permissions']


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Harvester details',
        description='Harvesters are the interface between the system and the raw data produced by cycler tests. They are responsible for uploading data to the system.',
        value={
            "url": "http://localhost:8001/harvesters/d8290e68-bfbb-3bc8-b621-5a9590aa29fd/",
            "uuid": "d8290e68-bfbb-3bc8-b621-5a9590aa29fd",
            "name": "Example Harvester",
            "sleep_time": 60,
            "environment_variables": {
                "EXAMPLE_ENV_VAR": "example value"
            },
            "active": True,
            "last_check_in": "2021-08-18T15:23:45.123456Z",
            "lab": "http://localhost:8001/labs/1/",
            "permissions": {
                "create": False,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class HarvesterSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    lab = TruncatedHyperlinkedRelatedIdField(
        'LabSerializer',
        ['name'],
        'lab-detail',
        read_only=True,
        help_text="Lab this Harvester belongs to"
    )

    class EnvField(serializers.DictField):
        # respresentation for json
        def to_representation(self, value) -> dict[str, str]:
            view = self.context.get('view')
            if view and view.action == 'list':
                return {}
            return {v.key: v.value for v in value.all() if not v.deleted}

        # representation for python object
        def to_internal_value(self, values):
            for k in values.keys():
                if not re.match(r'^[a-zA-Z0-9_]+$', k):
                    raise ValidationError(f'Key {k} is not alpha_numeric')
            for k, v in values.items():
                k = k.upper()
                try:
                    env = HarvesterEnvVar.objects.get(harvester=self.root.instance, key=k)
                    env.value = v
                    env.deleted = False
                    env.save()
                except HarvesterEnvVar.DoesNotExist:
                    HarvesterEnvVar.objects.create(harvester=self.root.instance, key=k, value=v)
            envvars = HarvesterEnvVar.objects.filter(harvester=self.root.instance, deleted=False)
            input_keys = [k.upper() for k in values.keys()]
            for v in envvars.all():
                if v.key not in input_keys:
                    v.deleted = True
                    v.save()
            return HarvesterEnvVar.objects.filter(harvester=self.root.instance, deleted=False)

    environment_variables = EnvField(help_text="Environment variables set on this Harvester")

    def validate_name(self, value):
        harvesters = Harvester.objects.filter(name=value)
        if self.instance is not None:
            harvesters = harvesters.exclude(uuid=self.instance.uuid)
            harvesters = harvesters.filter(lab=self.instance.lab)
        if harvesters.exists():
            raise ValidationError('Harvester with that name already exists')
        return value

    def validate_sleep_time(self, value):
        try:
            value = int(value)
            assert value > 0
            return value
        except (TypeError, ValueError, AssertionError):
            return ValidationError('sleep_time must be an integer greater than 0')

    class Meta:
        model = Harvester
        read_only_fields = ['url', 'uuid', 'last_check_in', 'lab', 'permissions']
        fields = [*read_only_fields, 'name', 'sleep_time', 'environment_variables', 'active']
        extra_kwargs = augment_extra_kwargs()

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Monitored Path details',
        description='Monitored Paths are subdirectories on Harvesters that are monitored for new files. When a new file is detected, it is uploaded to the system.',
        value={
            "url": "http://localhost:8001/monitored_paths/172f2460-9528-11ee-8454-eb9d381d3cc4/",
            "uuid": "172f2460-9528-11ee-8454-eb9d381d3cc4",
            "files": ["http://localhost:8001/files/c690ddf0-9527-11ee-8454-eb9d381d3cc4/"],
            "path": "/home/example_user/example_data.csv",
            "regex": ".*\\.csv",
            "stable_time": 60,
            "active": True,
            "harvester": "http://localhost:8001/harvesters/d8290e68-bfbb-3bc8-b621-5a9590aa29fd/",
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": False,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class MonitoredPathSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin, WithTeamMixin, CreateOnlyMixin):
    files = serializers.SerializerMethodField(help_text="Files on this MonitoredPath")
    edit_access_level = serializers.ChoiceField(
        choices=[(v.value, v.label) for v in ALLOWED_USER_LEVELS_EDIT_PATH],
        help_text="Minimum user level required to edit this resource",
        allow_null=True,
        required=False
    )

    def get_files(self, instance) -> list[OpenApiTypes.URI]:
        request = self.context['request']
        files = ObservedFile.objects.filter(harvester__lab=instance.team.lab)
        file_ids = []
        for file in files:
            if instance.matches(file.path):
                file_ids.append(file.uuid)
        data = ObservedFileSerializer(
            ObservedFile.objects.filter(uuid__in=file_ids),
            many=True,
            context={'request': request}
        ).data
        return [f['url'] for f in data]

    harvester = TruncatedHyperlinkedRelatedIdField(
        'HarvesterSerializer',
        ['name'],
        'harvester-detail',
        queryset=Harvester.objects.all(),
        help_text="Harvester this MonitoredPath is on",
        create_only=True
    )

    team = TruncatedHyperlinkedRelatedIdField(
        'TeamSerializer',
        ['name'],
        'team-detail',
        queryset=Team.objects.all(),
        help_text="Team this MonitoredPath belongs to",
        create_only=True
    )

    def validate_harvester(self, value):
        if self.instance is not None:
            return self.instance.harvester  # harvester cannot be changed
        request = self.context['request']
        if value.lab not in user_labs(request.user):
            raise ValidationError("You may only create MonitoredPaths on Harvesters in your own lab(s)")
        return value

    def validate_team(self, value):
        """
        Only team admins can create monitored paths.
        Monitored paths can read arbitrary files on the harvester system,
        so some level of trust is required to allow users to create them.
        """
        if self.instance is not None:
            return self.instance.team
        user = self.context['request'].user
        if value not in user_teams(user, True):
            raise ValidationError("You may only create MonitoredPaths in your own team(s)", code=HTTP_403_FORBIDDEN)
        return value

    def validate_path(self, value):
        try:
            value = str(value).lower().lstrip().rstrip()
        except BaseException as e:
            raise ValidationError(f"Invalid path: {e.__context__}")
        abs_path = os.path.abspath(value)
        return abs_path

    def validate_stable_time(self, value):
        try:
            v = int(value)
            assert v > 0
            return v
        except (TypeError, ValueError, AssertionError):
            raise ValidationError(f"stable_time value '{value}' is not a positive integer")

    def validate_regex(self, value):
        try:
            re.compile(value)
            return value
        except BaseException as e:
            raise ValidationError(f"Invalid regex: {e.__context__}")

    class Meta:
        model = MonitoredPath
        fields = [
            'url', 'uuid', 'path', 'regex', 'stable_time', 'active', 'files', 'harvester', 'team',
            'permissions', 'read_access_level', 'edit_access_level', 'delete_access_level'
        ]
        read_only_fields = ['url', 'uuid', 'files', 'harvester', 'permissions']
        extra_kwargs = augment_extra_kwargs({
            'harvester': {'create_only': True},
            'team': {'create_only': True}
        })


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Observed File details',
        description='Observed Files are the raw data produced by cycler tests. They are uploaded to the system by Harvesters.',
        value={
            "url": "http://localhost:8001/observed_files/1/",
            "uuid": "c690ddf0-9527-11ee-8454-eb9d381d3cc4",
            "path": "/home/example_user/example_data.csv",
            "name": "example_data.csv",
            "state": "IMPORTED",
            "parser": "Biologic",
            "num_rows": 100,
            "first_sample_no": 1,
            "last_sample_no": 100,
            "extra_metadata": {},
            "has_required_columns": True,
            "last_observed_time": "2021-08-18T15:23:45.123456Z",
            "last_observed_size": 123456,
            "upload_errors": [],
            "upload_info": {},
            "harvester": "http://localhost:8001/harvesters/d8290e68-bfbb-3bc8-b621-5a9590aa29fd/",
            "columns": [
                "http://localhost:8001/columns/1/",
                "http://localhost:8001/columns/2/",
                "http://localhost:8001/columns/3/"
            ],
            "column_errors": [],
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": False,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class ObservedFileSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    harvester = TruncatedHyperlinkedRelatedIdField(
        'HarvesterSerializer',
        ['name'],
        'harvester-detail',
        read_only=True,
        help_text="Harvester this File belongs to"
    )
    upload_info = serializers.SerializerMethodField(
        help_text="Metadata required for harvester program to resume file parsing"
    )
    has_required_columns = serializers.SerializerMethodField(
        help_text="Whether the file has all required columns"
    )
    columns = TruncatedHyperlinkedRelatedIdField(
        'DataColumnSerializer',
        ['name', 'data_type', 'unit', 'values'],
        view_name='datacolumn-detail',
        read_only=True,
        many=True,
        help_text="Columns extracted from this File"
    )
    column_errors = serializers.SerializerMethodField(
        help_text="Errors in uploaded columns"
    )

    def get_upload_info(self, instance) -> dict | None:
        if not self.context.get('with_upload_info'):
            return None
        try:
            last_record = 0
            columns = DataColumn.objects.filter(file=instance)
            column_data = []
            for c in columns:
                column_data.append({'name': c.name, 'id': c.id})
                if c.type.override_child_name == 'Sample_number':
                    last_record = c.values[:-1] if len(c.values) > 0 else 0
            return {
                'columns': column_data,
                'last_record_number': last_record
            }
        except BaseException as e:
            return {'columns': [], 'last_record_number': None, 'error': str(e)}

    def get_has_required_columns(self, instance) -> bool:
        return instance.has_required_columns()

    def get_column_errors(self, instance) -> list:
        return instance.column_errors()

    class Meta:
        model = ObservedFile
        read_only_fields = [
            'url', 'uuid', 'harvester', 'name', 'path',
            'state',
            'parser',
            'num_rows',
            'first_sample_no',
            'last_sample_no',
            'extra_metadata',
            'has_required_columns',
            'last_observed_time', 'last_observed_size', 'upload_errors',
            'column_errors',
            'upload_info', 'columns', 'permissions'
        ]
        fields = [*read_only_fields, 'name']
        extra_kwargs = augment_extra_kwargs({
            'upload_errors': {'help_text': "Errors associated with this File"}
        })

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Harvest Error details',
        description='Harvest Errors are errors encountered by Harvesters when uploading data to the system.',
        value={
            "url": "http://localhost:8001/harvest_errors/1/",
            "id": 1,
            "harvester": "http://localhost:8001/harvesters/d8290e68-bfbb-3bc8-b621-5a9590aa29fd/",
            "file": "http://localhost:8001/observed_files/1/",
            "error": "Error message",
            "timestamp": "2021-08-18T15:23:45.123456Z",
            "permissions": {
                "create": False,
                "destroy": False,
                "write": False,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class HarvestErrorSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    harvester = TruncatedHyperlinkedRelatedIdField(
        'HarvesterSerializer',
        ['name', 'lab'],
        'harvester-detail',
        read_only=True,
        help_text="Harvester this HarvestError belongs to"
    )
    file = TruncatedHyperlinkedRelatedIdField(
        'ObservedFileSerializer',
        ['path'],
        'observedfile-detail',
        read_only=True,
        help_text="File this HarvestError belongs to"
    )

    class Meta:
        model = HarvestError
        fields = ['url', 'id', 'harvester', 'file', 'error', 'timestamp', 'permissions']
        extra_kwargs = augment_extra_kwargs()


class DataUnitSerializer(serializers.ModelSerializer, PermissionsMixin):
    class Meta:
        model = DataUnit
        fields = ['url', 'id', 'name', 'symbol', 'description', 'permissions']
        extra_kwargs = augment_extra_kwargs()


class TimeseriesRangeLabelSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    data = serializers.SerializerMethodField()

    class Meta:
        model = TimeseriesRangeLabel
        fields = '__all__'
        extra_kwargs = augment_extra_kwargs()


class DataColumnTypeSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    class Meta:
        model = DataColumnType
        fields = ['url', 'id', 'name', 'description', 'is_default', 'unit', 'permissions']
        extra_kwargs = augment_extra_kwargs()


class DataColumnSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    """
    A column contains metadata and data. Data are an ordered list of values.
    """
    name = serializers.SerializerMethodField(help_text="Column name (assigned by harvester but overridden by Galv for core fields)")
    is_required_column = serializers.SerializerMethodField(help_text="Whether the column is one of those required by Galv")
    type_name = serializers.SerializerMethodField(help_text=get_model_field(DataColumnType, 'name').help_text)
    description = serializers.SerializerMethodField(help_text=get_model_field(DataColumnType, 'description').help_text)
    unit = serializers.SerializerMethodField(help_text=get_model_field(DataColumnType, 'unit').help_text)
    values = serializers.SerializerMethodField(help_text="Column values")
    file = TruncatedHyperlinkedRelatedIdField(
        'ObservedFileSerializer',
        ['harvester', 'path'],
        view_name='observedfile-detail',
        read_only=True,
        help_text="File this Column belongs to"
    )

    def get_name(self, instance) -> str:
        return instance.get_name()

    def get_is_required_column(self, instance) -> bool:
        return instance.type.is_required

    def get_type_name(self, instance) -> str:
        return instance.type.name

    def get_description(self, instance) -> str:
        return instance.type.description

    def get_unit(self, instance) -> dict[str, str] | None:
        return {
            k: v for k, v in
            DataUnitSerializer(instance.type.unit, context=self.context).data.items() \
            if k in ['url', 'id', 'name', 'symbol']
        }


    def get_values(self, instance) -> str:
        return reverse('datacolumn-values', args=(instance.id,), request=self.context['request'])

    class Meta:
        model = DataColumn
        fields = [
            'id',
            'url',
            'name',
            'name_in_file',
            'is_required_column',
            'file',
            'data_type',
            'type_name',
            'description',
            'unit',
            'values',
            'permissions'
        ]
        read_only_fields = fields
        extra_kwargs = augment_extra_kwargs()

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Experiment details',
        description='Experiments are the highest level of abstraction in the system. They are used to group cycler tests and define the protocol used in those tests.',
        value={
            "url": "http://localhost:8001/experiments/1/",
            "uuid": "d8290e68-bfbb-3bc8-b621-5a9590aa29fd",
            "title": "Example Experiment",
            "description": "Example description",
            "authors": [
                "http://localhost:8001/userproxies/1/"
            ],
            "protocol": {
                "detail": "JSON representation of experiment protocol"
            },
            "protocol_file": None,
            "cycler_tests": [
                "http://localhost:8001/cycler_tests/2b7313c9-94c2-4276-a4ee-e9d58d8a641b/"
            ],
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": True,
                "destroy": True,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class ExperimentSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin, WithTeamMixin):
    cycler_tests = TruncatedHyperlinkedRelatedIdField(
        'CyclerTestSerializer',
        ['cell', 'equipment', 'schedule'],
        'cyclertest-detail',
        queryset=CyclerTest.objects.all(),
        many=True,
        help_text="Cycler Tests using this Experiment"
    )
    authors = TruncatedHyperlinkedRelatedIdField(
        'UserSerializer',
        ['username', 'first_name', 'last_name'],
        'userproxy-detail',
        queryset=UserProxy.objects.all(),
        many=True,
        help_text="Users who created this Experiment"
    )

    class Meta:
        model = Experiment
        fields = [
            'url',
            'uuid',
            'title',
            'description',
            'authors',
            'protocol',
            'protocol_file',
            'cycler_tests',
            'team',
            'permissions'
        ]
        read_only_fields = ['url', 'uuid', 'permissions']
        extra_kwargs = augment_extra_kwargs()

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Validation Schema details',
        description='Validation Schemas are used to define the expected format of data.',
        value={
            "url": "http://localhost:8001/validation_schemas/1/",
            "uuid": "df383510-9527-11ee-8454-eb9d381d3cc4",
            "name": "Example Validation Schema",
            "schema": {
                "type": "object",
                "properties": {
                    "example_property": {
                        "type": "string"
                    }
                },
                "required": [
                    "example_property"
                ]
            },
            "team": "http://localhost:8001/teams/1/",
            "permissions": {
                "create": True,
                "destroy": True,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class ValidationSchemaSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin, WithTeamMixin):
    def validate_schema(self, value):
        try:
            jsonschema.validate({}, value)
        except jsonschema.exceptions.SchemaError as e:
            raise ValidationError(e)
        except jsonschema.exceptions.ValidationError:
            pass
        return value

    class Meta:
        model = ValidationSchema
        fields = [
            'url', 'uuid', 'team', 'name', 'schema',
            'permissions', 'read_access_level', 'edit_access_level', 'delete_access_level'
        ]

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Knox Token details',
        description='Knox Tokens are used to authenticate users with the system.',
        value={
            "url": "http://localhost:8001/tokens/1/",
            "id": 1,
            "name": "Example Token",
            "created": "2021-08-18T15:23:45.123456Z",
            "expiry": "2023-08-18T15:23:45.123456Z",
            "permissions": {
                "create": False,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class KnoxTokenSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    created = serializers.SerializerMethodField(help_text="Date and time of creation")
    expiry = serializers.SerializerMethodField(help_text="Date and time token expires (blank = never)")
    url = serializers.SerializerMethodField(help_text=url_help_text)

    def knox_token(self, instance):
        key, id = instance.knox_token_key.split('_')
        if not int(id) == self.context['request'].user.id:
            raise ValueError('Bad user ID for token access')
        return AuthToken.objects.get(user_id=int(id), token_key=key)

    def get_created(self, instance) -> timezone.datetime:
        return self.knox_token(instance).created

    def get_expiry(self, instance) -> timezone.datetime | None:
        return self.knox_token(instance).expiry

    def get_url(self, instance) -> str:
        return reverse('tokens-detail', args=(instance.id,), request=self.context['request'])

    class Meta:
        model = KnoxAuthToken
        fields = ['url', 'id', 'name', 'created', 'expiry']
        read_only_fields = ['url', 'id', 'created', 'expiry']
        extra_kwargs = augment_extra_kwargs()


@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Knox Token Full details',
        description='Knox Tokens are used to authenticate users with the system. This serializer includes the token value.',
        value={
            "url": "http://localhost:8001/tokens/1/",
            "id": 1,
            "name": "Example Token",
            "token": "example_token_value",
            "created": "2021-08-18T15:23:45.123456Z",
            "expiry": "2023-08-18T15:23:45.123456Z",
            "permissions": {
                "create": False,
                "destroy": False,
                "write": True,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class KnoxTokenFullSerializer(KnoxTokenSerializer):
    token = serializers.SerializerMethodField(help_text="Token value")

    def get_token(self, instance) -> str:
        return self.context['token']

    class Meta:
        model = KnoxAuthToken
        fields = ['url', 'id', 'name', 'created', 'expiry', 'token']
        read_only_fields = fields
        extra_kwargs = augment_extra_kwargs()

@extend_schema_serializer(examples = [
    OpenApiExample(
        'Valid example',
        summary='Harvester Configuration details',
        description='When Harvesters contact the system, they are given a configuration containing information about the system and the Harvester.',
        value={
            "url": "http://localhost:8001/harvesters/d8290e68-bfbb-3bc8-b621-5a9590aa29fd/",
            "uuid": "d8290e68-bfbb-3bc8-b621-5a9590aa29fd",
            "api_key": "example_api_key",
            "name": "Example Harvester",
            "sleep_time": 60,
            "monitored_paths": [
                "http://localhost:8001/monitored_paths/172f2460-9528-11ee-8454-eb9d381d3cc4/"
            ],
            "standard_units": [
                {
                    "url": "http://localhost:8001/data_units/1/",
                    "id": 1,
                    "name": "Example Unit",
                    "symbol": "e",
                    "description": "Example description"
                }
            ],
            "standard_columns": [
                {
                    "url": "http://localhost:8001/data_column_types/1/",
                    "id": 1,
                    "name": "Example Column Type",
                    "description": "Example description",
                    "is_default": True,
                    "unit": {
                        "url": "http://localhost:8001/data_units/1/",
                        "id": 1,
                        "name": "Example Unit",
                        "symbol": "e",
                        "description": "Example description"
                    }
                }
            ],
            "max_upload_bytes": 26214400,
            "environment_variables": {
                "EXAMPLE_ENV_VAR": "example value"
            },
            "deleted_environment_variables": [],
            "permissions": {
                "create": False,
                "destroy": False,
                "write": False,
                "read": True
            }
        },
        response_only=True, # signal that example only applies to responses
    ),
])
class HarvesterConfigSerializer(HarvesterSerializer, PermissionsMixin):
    standard_units = serializers.SerializerMethodField(help_text="Units recognised by the initial database")
    standard_columns = serializers.SerializerMethodField(help_text="Column Types recognised by the initial database")
    max_upload_bytes = serializers.SerializerMethodField(help_text="Maximum upload size (bytes)")
    deleted_environment_variables = serializers.SerializerMethodField(help_text="Envvars to unset")
    monitored_paths = MonitoredPathSerializer(many=True, read_only=True, help_text="Directories to harvest")

    @extend_schema_field(DataUnitSerializer(many=True))
    def get_standard_units(self, instance):
        return DataUnitSerializer(
            DataUnit.objects.filter(is_default=True),
            many=True,
            context={'request': self.context['request']}
        ).data

    @extend_schema_field(DataColumnTypeSerializer(many=True))
    def get_standard_columns(self, instance):
        # return []
        return DataColumnTypeSerializer(
            DataColumnType.objects.filter(is_default=True),
            many=True,
            context={'request': self.context['request']}
        ).data

    def get_max_upload_bytes(self, instance):
        return DATA_UPLOAD_MAX_MEMORY_SIZE

    def get_deleted_environment_variables(self, instance):
        return [v.key for v in instance.environment_variables.all() if v.deleted]

    class Meta:
        model = Harvester
        fields = [
            'url', 'uuid', 'api_key', 'name', 'sleep_time', 'monitored_paths',
            'standard_units', 'standard_columns', 'max_upload_bytes',
            'environment_variables', 'deleted_environment_variables', 'permissions'
        ]
        read_only_fields = fields
        extra_kwargs = augment_extra_kwargs({
            'environment_variables': {'help_text': "Envvars set on this Harvester"}
        })
        depth = 1


class HarvesterCreateSerializer(HarvesterSerializer, PermissionsMixin):
    lab = TruncatedHyperlinkedRelatedIdField(
        'LabSerializer',
        ['name'],
        'lab-detail',
        queryset=Lab.objects.all(),
        required=True,
        help_text="Lab this Harvester belongs to"
    )

    def validate_lab(self, value):
        try:
            if value in user_labs(self.context['request'].user, True):
                return value
        except:
            pass
        raise ValidationError("You may only create Harvesters in your own lab(s)")

    def to_representation(self, instance):
        return HarvesterConfigSerializer(context=self.context).to_representation(instance)

    class Meta:
        model = Harvester
        fields = ['name', 'lab', 'permissions']
        read_only_fields = ['permissions']
        extra_kwargs = {'name': {'required': True}, 'lab': {'required': True}}


class SchemaValidationSerializer(serializers.HyperlinkedModelSerializer, PermissionsMixin):
    schema = TruncatedHyperlinkedRelatedIdField(
        'ValidationSchemaSerializer',
        ['name'],
        'validationschema-detail',
        help_text="Validation schema used",
        read_only=True
    )

    validation_target = serializers.SerializerMethodField(help_text="Target of validation")

    def get_validation_target(self, instance) -> OpenApiTypes.URI:
        return reverse(
            f"{instance.content_type.model}-detail",
            args=(instance.object_id,),
            request=self.context['request']
        )

    class Meta:
        model = SchemaValidation
        fields = ['url', 'id', 'schema', 'validation_target', 'status', 'permissions', 'detail', 'last_update']
        read_only_fields = [*fields]
        extra_kwargs = augment_extra_kwargs()
