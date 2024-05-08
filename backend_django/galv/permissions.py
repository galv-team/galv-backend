# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

from django.db.models import Q
from dry_rest_permissions.generics import DRYPermissionFiltersBase
from .models import UserLevel, Lab, Team, GroupProxy


class HarvesterFilterBackend(DRYPermissionFiltersBase):
    action_routing = True

    def filter_list_queryset(self, request, queryset, view):
        key = request.META.get('HTTP_AUTHORIZATION', '')
        if key.startswith('Harvester '):
            return queryset.filter(api_key=key.split(' ')[1])
        labs = Lab.objects.filter(pk__in=get_user_auth_details(request).lab_ids)
        if len(labs) == 0:
            return queryset.none()
        return queryset.filter(lab__in=labs)

class LabFilterBackend(DRYPermissionFiltersBase):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        return queryset.filter(pk__in=get_user_auth_details(request).lab_ids)

class TeamFilterBackend(DRYPermissionFiltersBase):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        return queryset.filter(
            Q(pk__in=get_user_auth_details(request).team_ids)|
            Q(lab__pk__in=get_user_auth_details(request).writeable_lab_ids)
        )

class GroupFilterBackend(DRYPermissionFiltersBase):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        if request.user.is_superuser or request.user.is_staff:
            return queryset
        return queryset.filter(
            Q(editable_lab__pk__in=get_user_auth_details(request).lab_ids) |
            Q(editable_team__pk__in=get_user_auth_details(request).team_ids) |
            Q(readable_team__pk__in=get_user_auth_details(request).team_ids)
        )

class UserFilterBackend(DRYPermissionFiltersBase):
    action_routing = True

    @staticmethod
    def user_labs(user):
        lab_ids = set()
        for x in GroupProxy.objects.filter(user=user).all():
            if isinstance(x.owner, Lab):
                lab_ids.add(x.owner.pk)
            elif isinstance(x.owner, Team):
                lab_ids.add(x.owner.lab.pk)
        return lab_ids

    def filter_list_queryset(self, request, queryset, view):
        if request.user.is_superuser or request.user.is_staff or get_user_auth_details(request).is_lab_admin:
            return queryset
        all_users = queryset.all()
        users_to_return = []
        # see self and lab colleagues
        for user in all_users:
            if user == request.user or any(
                    [lab_id in get_user_auth_details(request).lab_ids for lab_id in UserFilterBackend.user_labs(user)]):
                users_to_return.append(user)
        return queryset.filter(pk__in=[u.pk for u in users_to_return])


class ObservedFileFilterBackend(DRYPermissionFiltersBase):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        return queryset.filter(monitored_paths__team__pk__in=get_user_auth_details(request).team_ids)


class ParquetPartitionFilterBackend(DRYPermissionFiltersBase):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        return queryset.filter(observed_file__monitored_paths__team__pk__in=get_user_auth_details(request).team_ids)


class ResourceFilterBackend(DRYPermissionFiltersBase):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        auth_details = get_user_auth_details(request)
        return queryset.filter(
            Q(team__pk__in=auth_details.team_ids) |
            (Q(read_access_level=UserLevel.LAB_MEMBER.value) & Q(team__lab__pk__in=auth_details.lab_ids)) |
            # Bit of a hack to chain True/False with Q object
            (Q(read_access_level=UserLevel.REGISTERED_USER.value) & Q(pk__isnull=not auth_details.is_approved)) |
            Q(read_access_level=UserLevel.ANONYMOUS.value)
        )

class SchemaValidationFilterBackend(ResourceFilterBackend):
    action_routing = True
    def filter_list_queryset(self, request, queryset, view):
        schemas = {q.schema for q in queryset}
        included_schemas = [s for s in schemas]
        for schema in schemas:
            if not schema.has_object_read_permission(request):
                included_schemas.remove(schema)
        return queryset.filter(schema__in=included_schemas)
