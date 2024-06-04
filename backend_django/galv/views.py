# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.
from __future__ import annotations

import cProfile
import datetime
import pstats
from pstats import SortKey

import knox.auth
import os

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, FileResponse
from django.urls import NoReverseMatch
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.types import OpenApiTypes
from dry_rest_permissions.generics import DRYPermissions
from rest_framework.mixins import ListModelMixin
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.reverse import reverse
from rest_framework.status import HTTP_404_NOT_FOUND
from rest_framework.views import APIView

from .models.models import _StorageType
from .serializers import HarvesterSerializer, \
    HarvesterCreateSerializer, \
    HarvesterConfigSerializer, \
    MonitoredPathSerializer, \
    ObservedFileSerializer, \
    CellSerializer, \
    EquipmentSerializer, \
    DataUnitSerializer, \
    UserSerializer, \
    TransparentGroupSerializer, \
    HarvestErrorSerializer, \
    KnoxTokenSerializer, \
    KnoxTokenFullSerializer, CellFamilySerializer, EquipmentFamilySerializer, \
    ScheduleSerializer, CyclerTestSerializer, ScheduleFamilySerializer, DataColumnTypeSerializer, DataColumnSerializer, \
    ExperimentSerializer, LabSerializer, TeamSerializer, ValidationSchemaSerializer, SchemaValidationSerializer, \
    ArbitraryFileSerializer, ArbitraryFileCreateSerializer, ParquetPartitionSerializer, ColumnMappingSerializer, \
    GalvStorageTypeSerializer, AdditionalS3StorageTypeSerializer
from .models import Harvester, \
    HarvestError, \
    MonitoredPath, \
    ObservedFile, \
    Cell, \
    Equipment, \
    DataUnit, \
    DataColumnType, \
    DataColumn, \
    FileState, \
    KnoxAuthToken, CellFamily, EquipmentTypes, EquipmentModels, EquipmentManufacturers, CellModels, CellManufacturers, \
    CellChemistries, CellFormFactors, ScheduleIdentifiers, EquipmentFamily, Schedule, CyclerTest, ScheduleFamily, \
    ValidationSchema, Experiment, Lab, Team, UserProxy, GroupProxy, ValidatableBySchemaMixin, SchemaValidation, \
    UserActivation, ALLOWED_USER_LEVELS_READ, ALLOWED_USER_LEVELS_EDIT, ALLOWED_USER_LEVELS_DELETE, \
    ALLOWED_USER_LEVELS_EDIT_PATH, ArbitraryFile, ParquetPartition, StorageError, ColumnMapping, GalvStorageType, \
    AdditionalS3StorageType
from .permissions import HarvesterFilterBackend, TeamFilterBackend, LabFilterBackend, GroupFilterBackend, \
    ResourceFilterBackend, ObservedFileFilterBackend, UserFilterBackend, SchemaValidationFilterBackend, \
    ParquetPartitionFilterBackend, LabResourceFilterBackend
from .serializers.utils import get_GetOrCreateTextStringSerializer
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import viewsets, serializers, permissions
from rest_framework.decorators import action, api_view, renderer_classes, parser_classes
from rest_framework.response import Response
from knox.views import LoginView as KnoxLoginView
from knox.views import LogoutView as KnoxLogoutView
from knox.views import LogoutAllView as KnoxLogoutAllView
from knox.models import AuthToken
from rest_framework.authentication import BasicAuthentication
from drf_spectacular.utils import extend_schema, extend_schema_view, inline_serializer, OpenApiResponse
import json
import time
import logging

from .storages import LocalDataStorage

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


GENERATE_HARVESTER_API_SCHEMA = os.getenv('GENERATE_HARVESTER_API_SCHEMA', "FALSE").upper()[0] != "F"


def checkpoint(msg: str, t: float, log_fun=logger.warning) -> float:
    t2 = time.time()
    log_fun(f"{msg} (in {round(t2 - t, 2)}s)")
    return t2


class ErrorSerializer(serializers.Serializer):
    error = serializers.CharField(help_text="Description of the error")


def error_response(error: str, status: int = 400) -> Response:
    print(f"Error: {error}")
    return Response({'error': error}, status=status)


def deserialize_datetime(serialized_value: str | float) -> timezone.datetime|None:
    if serialized_value is None:
        return None
    if isinstance(serialized_value, str):
        return timezone.make_aware(timezone.datetime.fromisoformat(serialized_value))
    if isinstance(serialized_value, float):
        return timezone.make_aware(timezone.datetime.fromtimestamp(serialized_value))
    raise TypeError


def lab_dependent_file_fetcher(parent_object, file_field_name: str):
    """
    Check a user is allowed to access a file, and redirect them to its actual location if they are.
    """
    try:
        file = getattr(parent_object, file_field_name)
        if file:
            if parent_object.storage_type and isinstance(parent_object.storage_type.get_storage(file), LocalDataStorage):
                # Send the file directly via the upstream nginx proxy
                response = HttpResponse()
                response["Content-Disposition"] = f"attachment; filename={file.name}"
                response['X-Accel-Redirect'] = file.backend_url()
            else:
                # Redirect to S3
                response = HttpResponseRedirect(file.backend_url())
            return response
    except Exception as e:
        logger.error(f"Error fetching file: {e}")
    return error_response("File not uploaded")

@extend_schema_view(
    list=extend_schema(responses={
        '200': {'type': 'string'}
    }),
)
class _GetOrCreateTextStringViewSet(ListModelMixin, viewsets.GenericViewSet):
    """
    Abstract base class for ViewSets that allow the creation of TextString objects.

    TextString objects are used to describe the properties of Cells, Equipment, and
    other objects used in experiments, making values available for autocompletion hints.
    """
    http_method_names = ['get', 'options']
    search_fields = ['@value']

    def list(self, *args, **kwargs):
        return super().list(*args, **kwargs)

    # @action(detail=True, methods=['GET'])
    # def details(self, request, pk: int = None):
    #     text_string = get_object_or_404(self.queryset, pk=pk)
    #     return Response(GetOrCreateTextStringSerializer(text_string).data)

@extend_schema(responses={200: inline_serializer(
    'ActivationResponse',
    {"detail": serializers.CharField()}
)})
@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def activate_user(request):
    # Request should have a token in the querystring
    token = request.GET.get('token')
    username = request.GET.get('username')
    if not username:
        return error_response("No username provided")
    try:
        user = UserProxy.objects.get(username=username, is_active=False)
    except UserProxy.DoesNotExist:
        return error_response(f"No user with username {username} requires activation")
    if request.GET.get('resend') == 'true':
        try:
            activation = UserActivation.objects.get(user=user)
            activation.send_email(request)
            return Response({"detail": f"Activation email sent for {username}"})
        except UserActivation.DoesNotExist:
            return error_response(f"Unable to send activation email for {username}")
    if not token:
        return error_response((
            f"No token provided. To send another token to your email address, "
            f"visit {reverse('activate_user', request=request)}?username={username}&resend=true"
        ))
    try:
        activation = UserActivation.objects.get(user=user, token=token)
        try:
            activation.activate_user()
        except ValueError as e:
            # Token expired - send another
            activation.send_email(request)
            raise e
    except (UserActivation.DoesNotExist, ValueError, RuntimeError) as e:
        return error_response(str(e))
    return Response({"detail": f"User {activation.user.username} activated"})


@extend_schema(responses={200: inline_serializer('PermittedAccessLevels', {
    "read_access_level": serializers.DictField(child=serializers.IntegerField()),
    "edit_access_level": serializers.DictField(child=serializers.IntegerField()),
    "delete_access_level": serializers.DictField(child=serializers.IntegerField()),
    "path.edit_access_level": serializers.DictField(child=serializers.IntegerField()),
})})
@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def access_levels(request):
    return Response({
        'read_access_level': {v.label: v.value for v in ALLOWED_USER_LEVELS_READ},
        'edit_access_level': {v.label: v.value for v in ALLOWED_USER_LEVELS_EDIT},
        'delete_access_level': {v.label: v.value for v in ALLOWED_USER_LEVELS_DELETE},
        'path.edit_access_level': {v.label: v.value for v in ALLOWED_USER_LEVELS_EDIT_PATH},
    })


@extend_schema(
    summary="Log in to retrieve an API Token for use elsewhere in the API.",
    description="""
Sign in with a username and password to obtain an API Token.
The token will allow you access to appropriate parts of the API in subsequent requests.

Subsequent requests should include the Authorization header with the content `Bearer token`
where token is the token you received in exchange for your credentials here.
    """,
    responses={
        200: inline_serializer(
            name='KnoxUser',
            fields={
                'expiry': serializers.DateTimeField(),
                'token': serializers.CharField(),
                'user': UserSerializer()
            }
        ),
        401: OpenApiResponse(description='Invalid username/password'),
    },
    request=None
)
class LoginView(KnoxLoginView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = [BasicAuthentication]
    http_method_names = ['post', 'options']

    def post(self, request, fmt=None):
        from django.contrib.auth.base_user import AbstractBaseUser
        if isinstance(request.user, AbstractBaseUser):
            return super(LoginView, self).post(request=request, format=fmt)
        return Response({'detail': "Anonymous login not allowed"}, status=401)

    def get_post_response_data(self, request, token, instance):
        user = UserProxy.objects.get(pk=request.user.pk)
        return {
            **UserSerializer(user, context={'request': request}).data,
            'token': token
        }

@extend_schema(
    summary="Log out current API Token.",
    description="""
Send a logout request to remove the token used to authenticate the request.
    """,
    responses={204: None, 401: OpenApiResponse(description='Unauthorized')},
    request=None
)
class LogoutView(KnoxLogoutView):
    http_method_names = ['get', 'options']
    authentication_classes = [knox.auth.TokenAuthentication]


@extend_schema(
    summary="Log out all API Tokens.",
    description="""
Remove all tokens associated with your account.
If you have numerous old or leaked tokens spread across numerous programs,
you can use this endpoint to easily revoke them all.
    """,
    responses={204: None, 401: OpenApiResponse(description='Unauthorized')},
    request=None
)
class LogoutAllView(KnoxLogoutAllView):
    http_method_names = ['get', 'options']
    authentication_classes = [knox.auth.TokenAuthentication]


@extend_schema(
    summary="Create a new API Token",
    description="""
Access to the API is authenticated by API Tokens.
When you log into the web frontend, you are issued with a temporary token
to allow your browser session to function.
If you wish to access the API via the Python client, or similar programmatically routes,
you will likely want a token with a longer expiry time. Those tokens are created using
this endpoint.
    """,
    request=inline_serializer('CreateKnoxToken', {
        'ttl': serializers.IntegerField(required=False, help_text="Time to live (s)"),
        'name': serializers.CharField()
    }),
    responses={
        200: KnoxTokenFullSerializer,
    }
)
class CreateTokenView(KnoxLoginView):
    """
    Create a new Knox Token.
    """
    http_method_names = ['post', 'options']

    def get_queryset(self):
        return KnoxAuthToken.objects.none().order_by('-id')

    def get_token_ttl(self):
        try:
            ttl = self.get_context()['request'].data.get('ttl', None)
            if ttl is not None:
                ttl = datetime.timedelta(seconds=int(ttl))
            return ttl
        except (AttributeError, KeyError, ValueError):
            return None

    def get_post_response_data(self, request, token, instance):
        error = None
        name = request.data.get('name')
        if not name:
            error = KeyError("Token must have a name")
        elif KnoxAuthToken.objects.filter(name=name, knox_token_key__regex=f"_{request.user.id}$").exists():
            error = ValueError("You already have a token with that name")
        if error:
            instance.delete()
            return error_response(str(error))
        else:
            token_wrapper = KnoxAuthToken.objects.create(
                name=name,
                knox_token_key=f"{instance.token_key}_{request.user.id}"
            )
        return KnoxTokenFullSerializer(token_wrapper, context={'request': request, 'token': token}).data


@extend_schema_view(
    list=extend_schema(
        summary="View tokens associated with your account.",
        description="""
List all API tokens associated with this user account.
You will not be able to see the value of the tokens themselves,
because these values are encrypted, but you can see the names you gave them and their expiry dates.

New Tokens cannot be created at this endpoint, use /create_token/ instead.
        """
    ),
    retrieve=extend_schema(
        summary="View a token associated with your account.",
        description="""
You will not be able to see the value of the token,
but you can see the name you gave it and its creation/expiry date.
        """,
    ),
    partial_update=extend_schema(
        summary="Change the name of a token associated with your account.",
        description="""
Token values and expiry dates are immutable, but you can change the name you
associated with a token.
        """
    ),
    destroy=extend_schema(
        summary="Revoke a token associated with your account.",
        description="""
Revoking a token renders that token invalid for authenticating requests to the API.
If you have tokens that are no longer needed, or that have been leaked (for example
by being included in a public Git Repository), you can should revoke them so that
other people cannot use them to access the API under your credentials.
        """
    )
)
class TokenViewSet(viewsets.ModelViewSet):
    """
    View and edit tokens associated with your account.
    """
    serializer_class = KnoxTokenSerializer
    queryset = KnoxAuthToken.objects.none().order_by('-id')
    http_method_names = ['get', 'patch', 'delete', 'options']
    permission_classes = [DRYPermissions]

    def get_queryset(self):
        token_keys = [f"{t.token_key}_{t.user_id}" for t in AuthToken.objects.filter(user_id=self.request.user.id)]
        # Create entries for temporary browser tokens
        for k in token_keys:
            if not KnoxAuthToken.objects.filter(knox_token_key=k).exists():
                KnoxAuthToken.objects.create(knox_token_key=k, name=f"Browser session [{k}]")
        return KnoxAuthToken.objects.filter(knox_token_key__in=token_keys).order_by('-id')

    def destroy(self, request, *args, **kwargs):
        try:
            token = KnoxAuthToken.objects.get(
                pk=kwargs.get('pk'),
                knox_token_key__regex=f"_{request.user.id}$"
            )
            self.check_object_permissions(self.request, token)
        except KnoxAuthToken.DoesNotExist:
            return error_response("Token not found")
        key, id = token.knox_token_key.split("_")
        AuthToken.objects.filter(user_id=int(id), token_key=key).delete()
        token.delete()
        return Response(status=204)


@extend_schema_view(
    list=extend_schema(
        summary="View all Labs",
        description="""
Labs are collections of Teams that provide for wider-scale access management and administration.
"""
    ),
    retrieve=extend_schema(
        summary="View a single Lab",
        description="""
Labs are collections of Teams that provide for wider-scale access management and administration.
"""
    ),
    create=extend_schema(
        summary="Create a new Lab",
        description="""
Labs are collections of Teams that provide for wider-scale access management and administration.
"""
    ),
    partial_update=extend_schema(
        summary="Update a Lab",
        description="""
Labs are collections of Teams that provide for wider-scale access management and administration.
"""
    )
)
class LabViewSet(viewsets.ModelViewSet):
    permission_classes = [DRYPermissions]
    filter_backends = [LabFilterBackend]
    filterset_fields = ['name']
    search_fields = ['@name']
    queryset = Lab.objects.all().order_by('-id')
    serializer_class = LabSerializer
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View all Labs",
        description="""
Teams are groups of Users who share Resources.
"""
    ),
    retrieve=extend_schema(
        summary="View a single Lab",
        description="""
Teams are groups of Users who share Resources.
"""
    ),
    create=extend_schema(
        summary="Create a new Lab",
        description="""
Teams are groups of Users who share Resources.
"""
    ),
    partial_update=extend_schema(
        summary="Update a Lab",
        description="""
Teams are groups of Users who share Resources.
"""
    )
)
class TeamViewSet(viewsets.ModelViewSet):
    permission_classes = [DRYPermissions]
    filter_backends = [TeamFilterBackend]
    serializer_class = TeamSerializer
    filterset_fields = ['name']
    search_fields = ['@name']
    queryset = Team.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View all Harvesters",
        description="""
Harvesters monitor a set of MonitoredPaths and send reports about ObservedFiles within those paths.
You can view all Harvesters for any Labs you are a member of.

Searchable fields:
- name
        """
    ),
    retrieve=extend_schema(
        summary="View a single Harvester",
        description="""
Harvesters monitor a set of MonitoredPaths and send reports about ObservedFiles within those paths.
        """
    ),
    create=extend_schema(
        exclude=not GENERATE_HARVESTER_API_SCHEMA,
        summary="Register the creation of a Harvester",
        description="""
A new Harvester created with the harvester program's `start.py` script will register itself via this endpoint.
This endpoint will register the Harvester and set up the user and administrator groups.
        """,
        request=HarvesterCreateSerializer(),
        responses={201: HarvesterConfigSerializer()}
    ),
    partial_update=extend_schema(
        summary="Update Harvester details",
        description="""
Some Harvester details can be updated after the Harvester is created.
Those details are updated using this endpoint.

Only Harvester Administrators are authorised to make these changes.
        """
    ),
    #     destroy=extend_schema(
    #         summary="Deactivate a Harvester",
    #         description="""
    # **Use with caution.**
    #
    # Only Harvester Administrators are authorised to delete harvesters.
    # Deleting a Harvester will not stop the harvester program running,
    # it will instead deactivate its API access.
    #         """
    #     ),
    config=extend_schema(
        exclude=not GENERATE_HARVESTER_API_SCHEMA,
        summary="Full configuration information for a Harvester",
        description="""
Only accessible to Harvesters.

Returns the full configuration information required by the harvester program to do its work.
This includes the Harvester specification, the Paths to monitor,
and information about standard Columns and Units.
        """
    ),
    report=extend_schema(
        exclude=not GENERATE_HARVESTER_API_SCHEMA,
        summary="Harvester-API communication",
        description="""
The harvester programs use the report endpoint for all information they send to the API
(except initial self-registration).
Reports will be file size reports, file parsing reports, or error reports.
File parsing reports may contain metadata or data to store.
        """,
        request=inline_serializer('HarvesterReportSerializer', {
            # TODO
        }),
        responses={
            # TODO
        }
    )
)
class HarvesterViewSet(viewsets.ModelViewSet):
    """
    Harvesters monitor a set of MonitoredPaths and send reports about ObservedFiles
    within those paths.
    A Harvester belongs to a Lab and its Monitored Paths are used by Teams within the Lab.

    When Harvesters communicate with the API they do so using special Harvester API Keys.
    These provide access to the report and configuration endpoints.

    Harvesters are created by a separate software package available within Galv.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [HarvesterFilterBackend]
    filterset_fields = ['name', 'lab_id']
    search_fields = ['@name']
    queryset = Harvester.objects.all().order_by('-last_check_in', '-id')
    http_method_names = ['get', 'post', 'patch', 'options']

    def get_serializer_class(self):
        if self.request.method.lower() == "post":
            return HarvesterCreateSerializer
        return HarvesterSerializer

    # # We do not actually destroy harvesters, just deactivate them
    # def destroy(self, request, *args, **kwargs):
    #     self.check_object_permissions(self.request, self.get_object())
    #     self.get_object().active = False
    #     self.get_object().save()
    #     return Response(self.get_serializer(self.get_object()).data, status=200)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        self.check_object_permissions(self.request, instance)
        # Strip out envvars unless this is an admin
        data = HarvesterSerializer(instance, context={'request': request}).data
        if not instance.has_object_write_permission(request):
            data.pop('environment_variables')
        return Response(data)

    @action(detail=True, methods=['GET'])
    def config(self, request, pk = None):
        """
        Return a full configuration file including MonitoredPaths under paths.

        Only available to Harvesters.
        """
        harvester = get_object_or_404(Harvester, id=pk)
        self.check_object_permissions(self.request, harvester)
        return Response(HarvesterConfigSerializer(
            harvester,
            context={'request': request}
        ).data)

    @action(detail=True, methods=['POST'])
    @parser_classes([JSONParser, MultiPartParser, FormParser])
    def report(self, request, pk = None):
        """
        Process a Harvester's report on its activity.
        This will spawn various other database updates depending on payload content.

        Reports come with a 'status' field, which can be one of:
        - error: The harvester encountered an error and is reporting it.
        - success: The harvester is reporting a successful task.

        If the status is 'error', the report must include an 'error' field.
        This field is in JSON or string format.
        The report may also include 'path' and 'monitored_path_id' fields.
        A blank response will be returned ({}).

        If the status is 'success', the report must include 'task', 'path', and 'monitored_path_id' fields.
        Path is the absolute path of the file being reported on.
        Monitored path id is the id of the monitored path the file was found in.
        The task field can be one of:
        - file_size: The harvester is reporting the size of a file.
        - import: The harvester is reporting the result of an import.

        If the task is 'file_size', the content must include a 'size' field.
        A representation of the file will be returned.

        If the task is 'import', the content must include a 'stage' field.
        Entries prefixed with * must also include a 'data' field.
        The stage field can be one of:
        - * file metadata: The harvester is beginning an import.
        - * column metadata: The harvester is reporting progress on an import.
        - * upload parquet partitions: The harvester is uploading datafiles.
        - * upload complete: The harvester has completed uploading files.
        - harvest complete: The harvester has completed an import.
        - harvest failed: The harvester has failed to import a file.
        These are stored as constants in the settings file.

        If the stage is 'file metadata', the data must include 'test_date', 'core_metadata' and 'extra_metadata' fields.
        It may also include a 'parser' field identifying the parser used to import the file.
        The core_metadata and extra_metadata fields must be dictionaries.
        - core_metadata may include:
            - Machine Type: The type of machine used to generate the file.
            - Dataset Name: The name of the dataset.
            - num_rows: The number of rows in the dataset.
            - first_sample_no: The number of the first sample in the dataset.
            - last_sample_no: The number of the last sample in the dataset.
        Extra metadata will be stored as a JSON.

        If the stage is 'column metadata', the data must include a 'metadata' field.
        This field will be a list of dictionaries, each representing a column of data.
        Each dictionary must include a 'data_type' field.
        Each dictionary must include one of 'column_id' or 'unit_id' or 'unit_symbol'.
        Dictionaries that specify 'unit_id' or 'unit_symbol' may also specify 'column_name'.
        Dictionaries must include a 'values' field, which is a list of values.

        A representation of the file will be returned.

        If the stage is 'upload parquet partitions', the data must include 'row_count', 'partition_count',
        and 'partition_number' fields describing the total rows in the dataset (derived by inspecting the parquet
         object), the number of parquet partitions into which it is split, and the number of the current partition.
        A file must also be uploaded as a form data field named 'file'.
        The response will be the serialized ParquetPartition object created in response.

        If the stage is 'upload complete', the data must include 'successes',
        the number of successful partition uploads, and errors, a list of errors encountered while uploading.

        If the stage is 'harvest complete' or 'harvest failed', no additional content is required.

        Only Harvesters are authorised to issue reports.
        """
        def handle_error_report(request, harvester):
            if request.data.get('error') is None:
                return error_response('error field required when status=error')
            error = request.data.get('error')
            if error is None:
                return error_response('error field required when status=error')
            if not isinstance(error, str):
                try:
                    error = json.dumps(error)
                except json.JSONDecodeError:
                    error = str(error)
            path = request.data.get('path')
            if path:
                HarvestError.objects.create(
                    harvester=harvester,
                    file=ObservedFile.objects.get_or_create(
                        harvester=harvester,
                        path=path,
                        defaults={'state': FileState.IMPORT_FAILED}
                    )[0],
                    error=str(error)
                )
            else:
                HarvestError.objects.create(
                    harvester=harvester,
                    error=str(error)
                )
            return Response({})

        def handle_file_size_report(harvester, path, monitored_path, content):
            # Harvester is reporting the size of a file
            # Update our database record and return a file status
            if content.get('size') is None:
                return error_response('file_size task requires content to include size field')

            file, _ = ObservedFile.objects.get_or_create(harvester=harvester, path=path)
            file.monitored_paths.add(monitored_path)

            size = content['size']
            if size < file.last_observed_size:
                file.state = FileState.UNSTABLE
            elif size > file.last_observed_size:
                file.state = FileState.GROWING

            if size != file.last_observed_size:
                file.last_observed_size = size
                file.last_observed_time = timezone.now()
            else:
                # Recent changes
                if file.last_observed_time + timezone.timedelta(seconds=monitored_path.stable_time) > timezone.now():
                    file.state = FileState.UNSTABLE
                # Stable file -- already imported?
                elif file.state not in [
                    FileState.IMPORTED,
                    FileState.IMPORT_FAILED,
                    FileState.MAP_ASSIGNED,
                    FileState.AWAITING_MAP_ASSIGNMENT
                ]:
                    file.state = FileState.STABLE

            file.save()
            return Response(ObservedFileSerializer(file, context={'request': self.request}).data)

        def handle_import_report(harvester, path, content, request):
            def handle_file_metadata(file, data):
                file.state = FileState.IMPORTING
                file.data_generation_date = deserialize_datetime(data['test_date'])
                if 'parser' in data:
                    file.parser = data['parser']

                core_metadata = data['core_metadata']
                extra_metadata = data['extra_metadata']
                if 'Machine Type' in core_metadata:
                    file.inferred_format = core_metadata.pop('Machine Type')
                if 'Dataset Name' in core_metadata:
                    file.name = core_metadata.pop('Dataset Name')
                if 'first_sample_no' in core_metadata:
                    file.first_sample_no = core_metadata.pop('first_sample_no')
                if 'last_sample_no' in core_metadata:
                    file.last_sample_no = core_metadata.pop('last_sample_no')
                if extra_metadata:
                    file.extra_metadata = extra_metadata
                file.core_metadata = core_metadata

            def handle_data_summary(file, data, request):
                try:
                    data = json.loads(data)
                except json.JSONDecodeError:
                    return error_response("Data summary must be a JSON string of the first few rows of the file")
                if not isinstance(data, dict):
                    return error_response("Data summary must be a dictionary")

                # data is a summary of the data in the file
                # If data are different to existing data, remove mapping
                # This prevents a user-assigned mapping being inappropriately applied
                if file.summary != data:
                    file.mapping = None
                    file.state = FileState.AWAITING_MAP_ASSIGNMENT

                file.summary = data
                file.save()

                # Check if we can assign a mapping automatically
                if file.mapping:
                    file.state = FileState.MAP_ASSIGNED
                    return
                mappings = file.applicable_mappings(request)
                mappings = [m for m in mappings if m['mapping'].is_valid]
                if mappings:
                    best = mappings[0]
                    if best['mapping'].is_valid:  # only assign if the mapping is valid
                        # If there's a tie for best mapping, don't assign (let the user choose later)
                        if len(mappings) == 1 or mappings[1]['missing'] > best['missing']:
                            file.mapping = best['mapping']
                            file.state = FileState.MAP_ASSIGNED
                            return
                file.state = FileState.AWAITING_MAP_ASSIGNMENT

            def handle_upload_parquets(file, data, request):
                try:
                    file.num_rows = data['total_row_count']
                    file.num_partitions = data['partition_count']
                    file.state = FileState.IMPORTING
                    file.save()
                    partition, _ = ParquetPartition.objects.get_or_create(
                        observed_file=file,
                        partition_number=data['partition_number']
                    )
                    partition.parquet_file.delete()
                    partition.parquet_file = request.FILES.get('parquet_file')
                    # partition.parquet_file.save()
                    partition.save()
                except StorageError as e:
                    return error_response(f"Error uploading file to storage: {e}")
                return Response(ParquetPartitionSerializer(partition, context={'request': request}).data)

            def handle_upload_complete(file, data):
                file.successful_uploads = data['successes']
                errors = data.get('errors', {})
                for i, e in errors.items():
                    pq = ParquetPartition.objects.get(observed_file=file, partition_number=i)
                    pq.upload_errors.append(e)
                    pq.save()

            def handle_upload_png(file, _, request):
                file.png = request.FILES.get('png_file')

            def handle_completion(file, stage, content):
                if stage == settings.HARVEST_STAGE_FAILED:
                    file.state = FileState.IMPORT_FAILED
                    if 'error' in content:
                        HarvestError.objects.create(harvester=harvester, file=file, error=content['error'])
                elif file.state == FileState.IMPORTING:
                    file.state = FileState.IMPORTED

            try:
                file = ObservedFile.objects.get(harvester=harvester, path=path)
            except ObservedFile.DoesNotExist:
                return error_response("ObservedFile does not exist")
            stage = content.get('stage')
            if stage is None:
                return error_response("'stage' field must be present where task=import")

            try:
                if stage == settings.HARVEST_STAGE_COMPLETE or stage == settings.HARVEST_STAGE_FAILED:
                    handle_completion(file, stage, content)
                else:
                    data = content.get('data')
                    if data is None:
                        return error_response("'data' field must be present where task=import")

                    if stage == settings.HARVEST_STAGE_FILE_METADATA:
                        handle_file_metadata(file, data)
                    elif stage == settings.HARVEST_STAGE_DATA_SUMMARY:
                        handle_data_summary(file, data, request)
                    elif stage == settings.HARVEST_STAGE_UPLOAD_PARQUET:
                        return handle_upload_parquets(file, data, request)  # return because we return the ParquetPartition
                    elif stage == settings.HARVEST_STAGE_UPLOAD_COMPLETE:
                        handle_upload_complete(file, data)
                    elif stage == settings.HARVEST_STAGE_UPLOAD_PNG:
                        handle_upload_png(file, data, request)
                    else:
                        return error_response("Unknown stage")

            except BaseException as e:
                file.state = FileState.IMPORT_FAILED
                HarvestError.objects.create(harvester=harvester, file=file, error=str(e))
                file.save()
                return error_response(f"Error importing data: {e.args}")

            file.save()

            return Response(ObservedFileSerializer(file, context={
                'request': self.request,
                'with_upload_info': content['stage'] == settings.HARVEST_STAGE_FILE_METADATA
            }).data)

        harvester = get_object_or_404(Harvester, id=pk)
        self.check_object_permissions(self.request, harvester)
        harvester.last_check_in = timezone.now()

        content = request.data.get('content')
        if request.data.get('content') is None and request.data.get('format') == 'flat':
            # Upload comes in a different format with the properties unnested.
            content = {
                'task': request.data.get('task'),
                'stage': request.data.get('stage'),
                'data': {
                    'filename': request.data.get('filename')
                }
            }
            if content['stage'] == settings.HARVEST_STAGE_UPLOAD_PARQUET:
                content['data']['total_row_count'] = int(float(request.data.get('total_row_count')))
                content['data']['partition_number'] = int(float(request.data.get('partition_number')))
                content['data']['partition_count'] = int(float(request.data.get('partition_count')))
        else:
            content = content or {}

        harvester.last_check_in_job = content.get('task', 'error_report')
        harvester.save()

        if request.data.get('status') == settings.HARVESTER_STATUS_ERROR:
            return handle_error_report(request, harvester)

        if request.data.get('status') != settings.HARVESTER_STATUS_SUCCESS:
            return error_response('Badly formatted request')

        try:
            path = request.data.get('path')
            assert path is not None
            path = os.path.normpath(path)
        except AssertionError:
            return error_response('Harvester report must specify a path')

        try:
            monitored_path_id = request.data.get('monitored_path_id')
            assert monitored_path_id is not None
            monitored_path = MonitoredPath.objects.get(id=monitored_path_id)
        except AssertionError:
            return error_response('Harvester report must specify a monitored_path_id')
        except MonitoredPath.DoesNotExist:
            return error_response('Harvester report must specify a valid monitored_path_id', 404)

        # Figure out what we succeeded in doing!
        if content is None:
            return error_response('content field required when status=success')
        task = content.get('task')
        if task is None:
            return error_response('content field must include task field')

        if task == settings.HARVESTER_TASK_FILE_SIZE:
            return handle_file_size_report(harvester, path, monitored_path, content)
        elif task == settings.HARVESTER_TASK_IMPORT:
            return handle_import_report(harvester, path, content, request)
        else:
            return error_response('Unrecognised task')


@extend_schema_view(
    list=extend_schema(
        summary="View Paths to which you have access",
        description="""
A Path refers to a directory accessible by a Harvester in which
data files will reside. Those files will be scanned periodically by the Harvester,
becoming ObservedFiles once they are reported to Galv by the Harvester.

Paths can be created or updated by a Harvester's admins and users, as
well as any users who have been given explicit permissions to edit the MonitoredPath.

Searchable fields:
- path
        """
    ),
    retrieve=extend_schema(
        summary="View the details of a Path",
        description="""
A Path refers to a directory accessible by a Harvester in which
data files will reside. Those files will be scanned periodically by the Harvester,
becoming ObservedFiles once they are reported to Galv by the Harvester.
        """
    ),
    create=extend_schema(
        summary="Create a new Path",
        description="""
Register a new directory on for a Harvester to crawl.
Files in that directory will be scanned periodically by the Harvester,
becoming ObservedFiles once they are reported to Galv by the Harvester.
        """,
        request=MonitoredPathSerializer(),
        responses={
            201: MonitoredPathSerializer()
        }
    ),
    destroy=extend_schema(
        summary="Delete a Path",
        description="""
Delete a directory from a Harvester's list of directories to crawl.
Files in that directory will no longer be scanned periodically by the Harvester,
and will no longer become ObservedFiles once they are reported to Galv by the Harvester.
        """
    ),
    partial_update=extend_schema(
        summary="Update a Path",
        description="""
Alter the path to the monitored directory,
or the time for which files need to be stable before being imported.
        """
    )
)
class MonitoredPathViewSet(viewsets.ModelViewSet):
    """
    A MonitoredPath refers to a directory accessible by a Harvester in which
    data files will reside. Those files will be scanned periodically by the Harvester,
    becoming ObservedFiles once they are reported to Galv by the Harvester.

    MonitoredPaths can be created or updated by a Harvester's admins and users, as
    well as any users who have been given explicit permissions to edit the MonitoredPath.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = MonitoredPathSerializer
    filterset_fields = ['path', 'harvester__id', 'harvester__name']
    search_fields = ['@path']
    queryset = MonitoredPath.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Files on a Path you can access",
        description="""
Files are files in a directory marked as a monitored Path for a Harvester.

They are reported to Galv by the harvester program.
An File will have file metadata (size, modification time), and a
status representing its import state. It may be linked to HarvestErrors
encountered while importing the file, and/or to Datasets representing the content
of imported files.

You can see all files on any Path on which you are an Administrator or User.
Harvester Administrators have access to all Files on the Harvester's Paths.

Searchable fields:
- path
- state
        """
    ),
    retrieve=extend_schema(
        summary="View a File",
        description="""
Files are files in a directory marked as a monitored Path for a Harvester.
        """
    ),
    reimport=extend_schema(
        summary="Force a File to be re-imported",
        description="""
A File will usually only be imported once, provided it is created, written to,
and then left alone. Files will naturally be reimported if they grow in size
again.
If an error was encountered while processing a file, or you have other reasons
for wishing to repeat the import process, you can use this endpoint to force the
harvester program to rerun the import process when it next scans the file.

*Note*: This request may be overwritten if the file changes size before it is next scanned.
        """
    )
)
class ObservedFileViewSet(viewsets.ModelViewSet):
    """
    ObservedFiles are files that exist (or have existed) in a MonitoredPath and have
    been reported to Galv by the Harvester.

    An ObservedFile instance will have file metadata (size, modification time), and a
    status representing its import state. It may be linked to HarvestErrors
    encountered while importing the file, and/or to Datasets representing the content
    of imported files.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ObservedFileFilterBackend]
    serializer_class = ObservedFileSerializer
    filterset_fields = ['harvester__id', 'path', 'state']
    search_fields = ['@path', 'state']
    queryset = ObservedFile.objects.all().order_by('-last_observed_time', '-id')
    http_method_names = ['get', 'patch', 'options']

    @action(detail=True, methods=['GET'])
    def reimport(self, request, pk = None):
        try:
            file = self.queryset.get(id=pk)
            self.check_object_permissions(self.request, file)
        except ObservedFile.DoesNotExist:
            return error_response('Requested file not found')
        file.state = FileState.RETRY_IMPORT
        file.storage_urls = []
        file.save()
        for dataset in file.parquet_partitions.all():
            dataset.delete()
        return Response(self.get_serializer(file, context={'request': request}).data)

    @action(detail=True, methods=['GET'])
    def applicable_mappings(self, request, pk = None):
        try:
            file = self.queryset.get(id=pk)
            self.check_object_permissions(self.request, file)
        except ObservedFile.DoesNotExist:
            return error_response('Requested file not found')
        mappings = file.applicable_mappings(request)
        for m in mappings:
            m['mapping'] = ColumnMappingSerializer(m['mapping'], context={'request': request}).data
        return Response(mappings)

    @action(detail=True, methods=['GET'])
    def summary(self, request, pk = None):
        try:
            file = self.queryset.get(id=pk)
            self.check_object_permissions(self.request, file)
        except ObservedFile.DoesNotExist:
            return error_response('Requested file not found')
        return Response(file.summary)

    @action(detail=True, methods=['GET'])
    def extra_metadata(self, request, pk = None):
        try:
            file = self.queryset.get(id=pk)
            self.check_object_permissions(self.request, file)
        except ObservedFile.DoesNotExist:
            return error_response('Requested file not found')
        return Response(file.extra_metadata)

    @action(detail=True, methods=['GET'])
    def png(self, request, pk = None):
        try:
            file = self.queryset.get(id=pk)
        except ObservedFile.DoesNotExist:
            return error_response('Requested file not found')
        self.check_object_permissions(self.request, file)
        return lab_dependent_file_fetcher(file, 'png')


class ColumnMappingViewSet(viewsets.ModelViewSet):
    permission_classes = [DRYPermissions]
    serializer_class = ColumnMappingSerializer
    queryset = ColumnMapping.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']

    def destroy(self, request, *args, **kwargs):
        try:
            mapping = self.get_object()
            self.check_object_permissions(self.request, mapping)
        except ColumnMapping.DoesNotExist:
            return error_response("Mapping not found")
        if (mapping.in_use and
                not all([
                    f.has_object_write_permission(request=request)
                    for f in mapping.observed_files.all()
                ])
        ):
            return error_response("You cannot modify a mapping that is in use by files you cannot write to.")
        if mapping.in_use:
            return error_response("Mapping is in use and cannot be deleted")
        return super().destroy(request, *args, **kwargs)




@extend_schema_view(
    file=extend_schema(
        summary="Download a file",
        description="""
Download a file from the API.
        """,
        responses={200: OpenApiTypes.BINARY}
    )
)
class ParquetPartitionViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [DRYPermissions]
    filter_backends = [ParquetPartitionFilterBackend]
    serializer_class = ParquetPartitionSerializer
    queryset = ParquetPartition.objects.all().order_by('-observed_file__id', 'partition_number')

    @action(detail=True, methods=['GET'])
    def file(self, request, pk = None):
        try:
            partition = self.queryset.get(id=pk)
        except ParquetPartition.DoesNotExist:
            return error_response('Requested partition not found')
        self.check_object_permissions(self.request, partition)
        return lab_dependent_file_fetcher(partition, 'parquet_file')


@extend_schema_view(
    list=extend_schema(
        summary="View Errors encountered while Harvesting",
        description="""
View the Errors encountered by Harvesters to which you have access.

Harvesters report errors when they encounter them, either in crawling or in processing files.
If a File or Dataset is not appearing on a Path where you think it should be, this is the first place to check.

Searchable fields:
- error
        """
    ),
    retrieve=extend_schema(
        summary="View Error details",
        description="""
View an Error reported by a Harvester.
        """
    )
)
class HarvestErrorViewSet(viewsets.ReadOnlyModelViewSet):
    """
    HarvestErrors are problems encountered by Harvesters during the crawling of
    MonitoredPaths or the importing or inspection of ObservedFiles.
    """
    permission_classes = [DRYPermissions]
    serializer_class = HarvestErrorSerializer
    filterset_fields = ['file', 'harvester']
    search_fields = ['@error']
    queryset = HarvestError.objects.all().order_by('-timestamp')


class EquipmentTypesViewSet(_GetOrCreateTextStringViewSet):
    """
    Equipment Types are used to describe the type of equipment used in an experiment.
    Examples are "Thermal Chamber", "Cycler".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(EquipmentTypes)
    queryset = EquipmentTypes.objects.filter(include_in_autocomplete=True).order_by('value')


class EquipmentModelsViewSet(_GetOrCreateTextStringViewSet):
    """
    Equipment Models are used to describe the model of equipment used in an experiment.
    Examples are "BT-2000", "BT-2043".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(EquipmentModels)
    queryset = EquipmentModels.objects.filter(include_in_autocomplete=True).order_by('value')
class EquipmentManufacturersViewSet(_GetOrCreateTextStringViewSet):
    """
    Equipment Manufacturers are used to describe the manufacturer of equipment used in an experiment.
    Examples are "Arbin", "Maccor".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(EquipmentManufacturers)
    queryset = EquipmentManufacturers.objects.filter(include_in_autocomplete=True).order_by('value')
class CellModelsViewSet(_GetOrCreateTextStringViewSet):
    """
    Cell Models are used to describe the model of cell used in an experiment.
    Examples are "VTC6", "HG2".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(CellModels)
    queryset = CellModels.objects.filter(include_in_autocomplete=True).order_by('value')
class CellManufacturersViewSet(_GetOrCreateTextStringViewSet):
    """
    Cell Manufacturers are used to describe the manufacturer of cell used in an experiment.
    Examples are "Sony", "LG".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(CellManufacturers)
    queryset = CellManufacturers.objects.filter(include_in_autocomplete=True).order_by('value')
class CellChemistriesViewSet(_GetOrCreateTextStringViewSet):
    """
    Cell Chemistries are used to describe the chemistry of cell used in an experiment.
    Examples are "NMC", "LFP".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(CellChemistries)
    queryset = CellChemistries.objects.filter(include_in_autocomplete=True).order_by('value')
class CellFormFactorsViewSet(_GetOrCreateTextStringViewSet):
    """
    Cell Form Factors are used to describe the form factor of cell used in an experiment.
    Examples are "Pouch", "Cylindrical".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(CellFormFactors)
    queryset = CellFormFactors.objects.filter(include_in_autocomplete=True).order_by('value')
class ScheduleIdentifiersViewSet(_GetOrCreateTextStringViewSet):
    """
    Schedule Identifiers are used to describe the type of schedule used in an experiment.
    Examples are "Cell Conditioning", "Pseudo-OCV".
    """
    def get_serializer_class(self):
        return get_GetOrCreateTextStringSerializer(ScheduleIdentifiers)
    queryset = ScheduleIdentifiers.objects.filter(include_in_autocomplete=True).order_by('value')


@extend_schema_view(
    list=extend_schema(
        summary="View Cell Families",
        description="""
Cell Families group together the general properties of a type of Cell.
Each Cell is associated with a Cell Family.

Searchable fields:
- name
- manufacturer
- form_factor
        """
    ),
    retrieve=extend_schema(
        summary="View a Cell Family",
        description="""
Cell Families group together the general properties of a type of Cell.
Each Cell is associated with a Cell Family.
        """
    ),
    create=extend_schema(
        summary="Create a Cell Family",
        description="""
Cell Families group together the general properties of a type of Cell.
Each Cell is associated with a Cell Family.
        """
    ),
    partial_update=extend_schema(
        summary="Update a Cell Family",
        description="""
Cell Families that do not have any Cells associated with them may be edited.
Cell Families that _do_ have Cells associated with them are locked,
to prevent accidental updating.
        """
    ),
    destroy=extend_schema(
        summary="Delete a Cell Family",
        description="""
Cell Families that do not have any Cells associated with them may be deleted.
Cell Families that _do_ have Cells associated with them are locked,
to prevent accidental updating.
        """
    )
)
class CellFamilyViewSet(viewsets.ModelViewSet):
    """
    CellFamilies describe types of Cell.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = CellFamilySerializer
    filterset_fields = [
        'model', 'form_factor', 'chemistry', 'nominal_capacity', 'manufacturer'
    ]
    search_fields = ['@model', '@manufacturer', '@form_factor']
    queryset = CellFamily.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Cells",
        description="""
Cells are specific cells which generate data stored in Datasets/observed Files.

Searchable fields:
- identifier
        """
    ),
    retrieve=extend_schema(
        summary="View a Cell",
        description="""
Cells are specific cells which generate data stored in Datasets/observed Files.
        """
    ),
    create=extend_schema(
        summary="Create a Cell",
        description="""
Create an instance of a Cell by declaring its unique identifier and associated Cell Family.
        """
    ),
    partial_update=extend_schema(
        summary="Update a Cell",
        description="""
Cells that are not used in Cycler Tests may be edited.
Cells that _are_ used in a Cycler Tests are locked to prevent accidental updating.
        """
    ),
    destroy=extend_schema(
        summary="Delete a Cell",
        description="""
Cells that are not used in Cycler Tests may be deleted.
Cells that _are_ used in a Cycler Tests are locked to prevent accidental updating.
        """
    ),
    rdf=extend_schema(
        summary="View a Cell in RDF (JSON-LD)",
        description="""
Dump the Cell in RDF (JSON-LD) format.
        """
    )
)
class CellViewSet(viewsets.ModelViewSet):
    """
    Cells are specific cells which have generated data stored in Datasets/ObservedFiles.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = CellSerializer
    filterset_fields = ['identifier', 'family__id']
    search_fields = ['@identifier', '@family__model', '@family__manufacturer']
    queryset = Cell.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']

    @action(detail=True, methods=['get'])
    def rdf(self, request, pk=None):
        """
        Dump the Cell in RDF (JSON-LD) format.
        """
        cell = self.get_object()
        self.check_object_permissions(self.request, cell)
        return Response(cell.__json_ld__())


@extend_schema_view(
    list=extend_schema(
        summary="View Equipment Families",
        description="""
Equipment Families group together the general properties of a type of Equipment.
Each Equipment is associated with an Equipment Family.

Searchable fields:
- type
- manufacturer
- form_factor
        """
    ),
    retrieve=extend_schema(
        summary="View an Equipment Family",
        description="""
Equipment Families group together the general properties of a type of Equipment.
Each Equipment is associated with an Equipment Family.
        """
    ),
    create=extend_schema(
        summary="Create an Equipment Family",
        description="""
Equipment Families group together the general properties of a type of Equipment.
Each Equipment is associated with an Equipment Family.
        """
    ),
    partial_update=extend_schema(
        summary="Update an Equipment Family",
        description="""
Equipment Families that do not have any Equipment associated with them may be edited.
Equipment Families that _do_ have Equipment associated with them are locked,
to prevent accidental updating.
        """
    ),
    destroy=extend_schema(
        summary="Delete an Equipment Family",
        description="""
Equipment Families that do not have any Equipment associated with them may be deleted.
Equipment Families that _do_ have Equipment associated with them are locked,
to prevent accidental updating.
        """
    )
)
class EquipmentFamilyViewSet(viewsets.ModelViewSet):
    """
    EquipmentFamilies describe types of Equipment.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = EquipmentFamilySerializer
    filterset_fields = [
        'model', 'type', 'manufacturer'
    ]
    search_fields = ['@model', '@manufacturer', '@type']
    queryset = EquipmentFamily.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Equipment",
        description="""
Experimental equipment used in experiments which generate Files and their Cycler Tests.

Searchable fields:
- name
- type
        """
    ),
    retrieve=extend_schema(
        summary="View specific Equipment",
        description="""
Experimental equipment used in experiments which generate Files and their Cycler Tests.
        """
    ),
    create=extend_schema(
        summary="Create Equipment",
        description="""
Create Equipment by describing its role and purpose.
        """
    ),
    partial_update=extend_schema(
        summary="Update Equipment",
        description="""
Equipment that is not used in Cycler Tests may be edited.
Equipment that _is_ used in a Cycler Tests is locked to prevent accidental updating.
        """
    ),
    destroy=extend_schema(
        summary="Delete Equipment",
        description="""
Equipment that is not used in Cycler Tests may be deleted.
Equipment that _is_ used in a Cycler Tests is locked to prevent accidental updating.
        """
    )
)
class EquipmentViewSet(viewsets.ModelViewSet):
    """
    Equipment can be attached to Datasets and used to view Datasets which
    have used similar equipment.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = EquipmentSerializer
    queryset = Equipment.objects.all()
    filterset_fields = ['family__type']
    search_fields = ['@identifier', '@family__type']
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Equipment Families",
        description="""
Equipment Families group together the general properties of a type of Equipment.
Each Equipment is associated with an Equipment Family.

Searchable fields:
- type
- manufacturer
- form_factor
        """
    ),
    retrieve=extend_schema(
        summary="View a Schedule Family",
        description="""
Schedule Families group together the general properties of a type of Schedule.
Each Schedule is associated with a Schedule Family.
        """
    ),
    create=extend_schema(
        summary="Create a Schedule Family",
        description="""
Schedule Families group together the general properties of a type of Schedule.
Each Schedule is associated with a Schedule Family.
        """
    ),
    partial_update=extend_schema(
        summary="Update a Schedule Family",
        description="""
Schedule Families that do not have a Schedule associated with them may be edited.
Schedule Families that _do_ have Schedule associated with them are locked,
to prevent accidental updating.
        """
    ),
    destroy=extend_schema(
        summary="Delete a Schedule Family",
        description="""
Schedule Families that do not have a Schedule associated with them may be deleted.
Schedule Families that _do_ have Schedule associated with them are locked,
to prevent accidental updating.
        """
    )
)
class ScheduleFamilyViewSet(viewsets.ModelViewSet):
    """
    Schedules can be attached to Cycler Tests and used to view Cycler Tests which
    have used similar equipment.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = ScheduleFamilySerializer
    queryset = ScheduleFamily.objects.all()
    search_fields = ['@identifier', '@description']
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Schedule",
        description="""
Schedule used in experiments which generate Files and their Datasets.

Searchable fields:
- identifier
- description
        """
    ),
    retrieve=extend_schema(
        summary="View specific Schedule",
        description="""
Schedule used in experiments which generate Files and their Datasets.
        """
    ),
    create=extend_schema(
        summary="Create Schedule",
        description="""
Create a Schedule by describing its role and purpose.
        """
    ),
    partial_update=extend_schema(
        summary="Update Schedule",
        description="""
Schedules that is not used in Cycler Tests may be edited.
Schedules that _is_ used in a Cycler Tests is locked to prevent accidental updating.
        """
    ),
    destroy=extend_schema(
        summary="Delete Schedule",
        description="""
Schedules that is not used in Cycler Tests may be deleted.
Schedules that _is_ used in a Cycler Tests is locked to prevent accidental updating.
        """
    )
)
class ScheduleViewSet(viewsets.ModelViewSet):
    """
    Schedules can be attached to Cycler Tests and used to view Cycler Tests which
    have used similar equipment.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = ScheduleSerializer
    queryset = Schedule.objects.all()
    search_fields = ['@family__identifier']
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']

class CyclerTestViewSet(viewsets.ModelViewSet):
    """
    Cycler Tests are the primary object in the database.
    They represent a single test conducted on a specific cell using specific equipment,
    according to a specific schedule.

    The test produces a dataset which can be associated with the Cycler Test,
    and Cycler Tests can be grouped together into Experiments.
    """
    serializer_class = CyclerTestSerializer
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    queryset = CyclerTest.objects.all()
    search_fields = ['@cell__id', '@schedule__identifier']
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Experiments",
        description="""
Experiments are collections of Cycler Tests which are grouped together for analysis.
        """
    ),
    retrieve=extend_schema(
        summary="View an Experiment",
        description="""
Experiments are collections of Cycler Tests which are grouped together for analysis.
        """
    ),
    create=extend_schema(
        summary="Create an Experiment",
        description="""
Experiments are collections of Cycler Tests which are grouped together for analysis.
        """
    )
)
class ExperimentViewSet(viewsets.ModelViewSet):
    """
    Experiments are collections of Cycler Tests which are grouped together for analysis.
    """
    serializer_class = ExperimentSerializer
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    queryset = Experiment.objects.all()
    search_fields = ['@title', '@description']
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Units",
        description="""
Units are scientific (typically SI) units which describe how data map to quantities in the world.
Some Units are predefined (e.g. seconds, volts, amps, unitless quantities),
while others can be defined in experimental data.

Searchable fields:
- name
- symbol
- description
        """
    ),
    retrieve=extend_schema(
        summary="View a Unit",
        description="""
Units are scientific (typically SI) units which describe how data map to quantities in the world.
Some Units are predefined (e.g. seconds, volts, amps, unitless quantities),
while others can be defined in experimental data.
        """
    )
)
class DataUnitViewSet(viewsets.ModelViewSet):
    """
    DataUnits are units used to characterise data in a DataColumn.
    """
    serializer_class = DataUnitSerializer
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    filterset_fields = ['name', 'symbol', 'is_default']
    search_fields = ['@name', '@symbol', '@description']
    queryset = DataUnit.objects.all().order_by('id')
    http_method_names = ['get', 'post', 'patch', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Column Types",
        description="""
Column Types are generic Column templates. They hold the metadata for a Column,
while the individual Column instances link Column Types to the TimeseriesData they contain.

Some Column Types are innately recognised by Galv and its harvester parsers,
while others can be defined by the parsers during data processing.

Searchable fields:
- name
- description
        """
    ),
    retrieve=extend_schema(
        summary="View a Column Type",
        description="""
Column Types are generic Column templates. They hold the metadata for a Column,
while the individual Column instances link Column Types to the TimeseriesData they contain.

Some Column Types are innately recognised by Galv and its harvester parsers,
while others can be defined by the parsers during data processing.

Searchable fields:
- name
- description
        """
    )
)
class DataColumnTypeViewSet(viewsets.ModelViewSet):
    """
    DataColumnTypes support reuse of DataColumns over multiple DataSets
    by abstracting their information.
    """
    serializer_class = DataColumnTypeSerializer
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    filterset_fields = ['name', 'unit__symbol', 'unit__name', 'is_default']
    search_fields = ['@name', '@description']
    queryset = DataColumnType.objects.all().order_by('id')
    http_method_names = ['get', 'post', 'patch', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Columns to which you have access",
        description="""
Column instances link Column Types to the TimeseriesData they contain.
You can access any Column in any Dataset to which you have access.

Searchable fields:
- dataset__name
- type__name (Column Type name)
        """
    ),
    retrieve=extend_schema(
        summary="View a Column",
        description="""
Column instances link Column Types to the TimeseriesData they contain.

Searchable fields:
- dataset__name
- type__name (Column Type name)
        """
    )
)
class DataColumnViewSet(viewsets.ModelViewSet):
    """
    DataColumns describe which columns are in a Dataset's data.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = DataColumnSerializer
    filterset_fields = ['file__id', 'type__is_required', 'file__name', 'type__unit__symbol', 'type__id', 'type__name']
    search_fields = ['@file__name', '@type__name']
    queryset = DataColumn.objects.all().order_by('-file__id', '-id')
    http_method_names = ['get', 'patch', 'options']


# @extend_schema_view(
#     list=extend_schema(
#         summary="View time-series range labels to which you have access",
#         description="""
# Labels marking blocks of contiguous time series data.
#
# Searchable fields:
# - label
#         """
#     ),
#     retrieve=extend_schema(
#         summary="View a specific label.",
#         description="""
# Labels marking blocks of contiguous time series data.
#         """
#     ),
#     create=extend_schema(
#         summary="Create a label.",
#         description="""
# Create a label with a description.
#         """
#     ),
#     destroy=extend_schema(
#         summary="Delete a label.",
#         description="""
# RangeLabels not used in any Dataset may be deleted.
#         """
#     )
# )
# class TimeseriesRangeLabelViewSet(viewsets.ModelViewSet):
#     """
#     TimeseriesRangeLabels mark contiguous observations using start and endpoints.
#     """
#     serializer_class = TimeseriesRangeLabelSerializer
#     queryset = TimeseriesRangeLabel.objects.all().order_by('id')
#     filterset_fields = ['label', 'info']
#     search_fields = ['@label']
#     http_method_names = ['get', 'post', 'patch', 'delete', 'options']


@extend_schema_view(
    partial_update=extend_schema(
        summary="Update User profile",
        description="""
Your User profile can be updated. You may change your email address and password.
All changes require your current password to be accepted.
        """,
        request=inline_serializer('UserUpdate', {
            'email': serializers.EmailField(help_text="Your updated email"),
            'password': serializers.CharField(help_text="Your new password"),
            'currentPassword': serializers.CharField(help_text="Your current password", required=True)
        }),
        responses={
            200: UserSerializer,
            401: ErrorSerializer,
            404: ErrorSerializer
        }
    )
)
class UserViewSet(viewsets.ModelViewSet):
    """
    Users are Django User instances custom-serialized for convenience.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [UserFilterBackend]
    serializer_class = UserSerializer
    queryset = UserProxy.objects.filter(is_active=True).order_by('id')
    http_method_names = ['get', 'post', 'patch', 'options']


class GroupViewSet(viewsets.ModelViewSet):
    """
    Groups are Django Group instances custom-serialized for convenience.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [GroupFilterBackend]
    serializer_class = TransparentGroupSerializer
    queryset = GroupProxy.objects.all()
    http_method_names = ['patch', 'options', 'get']

    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)


@extend_schema_view(
    list=extend_schema(
        summary="List all Validation Schemas",
        description="""
Validation schemas contain one or more definitions that describe requirements for Galv objects.
The possible values are available at `/keys/` and should be implemented in your schema thus:

```json
{
    ...
    "$defs": {
        "key_name": {
            ... description
        },
        ... and so on for any other keys
    },
    ...
```

For each of these schemas that is enabled, Galv will test the objects against the definition
by constructing a JSON Schema file that hooks in your definitions and asserts a single object.
This means you need not specify a root object (e.g. with `"type": "object"`) in your schema.

```json
{
    ...
    "type": {"$ref": "#/$defs/key_name"}
}
```

Because your definitions are included locally, you can include references to other definitions in your schema, 
and Galv will automatically resolve them for you.

Galv will highlight any objects that do not meet the requirements.
This can allow you to specify a series of increasingly strict requirements for your lab's metadata.

Schemas are validated against _individually_, and are not checked for consistency.
If you declare that a particular field is a `string` in one schema and a `number` in another, 
Galv will not complain, except to issue a warning for failing to adhere to one or the other schema.

Because schemas validate objects returned from the Galv API, 
schemas should expect most relational fields to be represented as URLs. 

Note: there are some requirements put in place by Galv's database structure. 
These will always apply, and will generate errors rather than warnings.
"""
    ),
    keys=extend_schema(
        summary="Keys available for validation schemas",
        description="""
Validation schemas contain one or more root properties that describe requirements for Galv objects.
This endpoint provides the names and list URLs for each Galv object that can be validated against a schema.
        """,
        responses={
            200: inline_serializer('ValidationSchemaRootKeys', {
                'key': serializers.CharField(help_text="Name of the root key"),
                'describes': serializers.CharField(help_text="URL of the objects the key describes"),
            })
        }
    )
)
class ValidationSchemaViewSet(viewsets.ModelViewSet):
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    serializer_class = ValidationSchemaSerializer
    queryset = ValidationSchema.objects.all().order_by('-id')

    @action(methods=['get'], detail=False)
    def keys(self, request):
        """
        Return the possible root keys for a validation schema.
        This consists of all models that extend the JSONModel or UUIDModel classes.
        """
        def url(s):
            try:
                return reverse(f"{s.lower()}-list", request=request)
            except NoReverseMatch:
                return None

        return Response([{
            'key': m.__name__,
            'describes': url(m.__name__)
        } for m in ValidatableBySchemaMixin.__subclasses__() if url(m.__name__) is not None]
        )


class SchemaValidationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    SchemaValidations are the results of validating Galv objects against ValidationSchemas.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [SchemaValidationFilterBackend]
    filter_fields = ['schema__id', 'object_id', 'content_type__model']
    serializer_class = SchemaValidationSerializer
    queryset = SchemaValidation.objects.all().order_by('-last_update')

    def list(self, request, *args, **kwargs):
        """
        List SchemaValidations, optionally filtering by schema, object, or content type.
        """
        for sv in self.queryset:
            sv.validate()
            sv.save()
        return super().list(request, *args, **kwargs)

@extend_schema_view(
    create=extend_schema(
        summary="Upload a file",
        description="""
Upload a file along with its metadata. The file will be stored in an AWS S3 bucket.

Files with `is_public` set to `True` will be available to the public.
Files with `is_public` set to `False` will only be displayed as links which will provide access for 1 hour,
after which the link must be retrieved again.
        """,
        request={
            'multipart/form-data': ArbitraryFileCreateSerializer,
            'application/x-www-form-urlencoded': ArbitraryFileCreateSerializer
        },
        responses={
            201: ArbitraryFileSerializer
        }
    ),
    partial_update=extend_schema(
        summary="Update a file's metadata",
        description="""
You can change the visibility of a file and its metadata. Files themselves cannot be updated, only deleted.
        """,
        request=ArbitraryFileSerializer,
        responses={
            200: ArbitraryFileSerializer
        }
    ),
    destroy=extend_schema(
        summary="Delete a file",
        description="""Delete a file from the database and from the S3 bucket."""
    )
)
class ArbitraryFileViewSet(viewsets.ModelViewSet):
    """
    ArbitraryFiles are files that are not observed by the harvester, and are not
    associated with any specific experiment or dataset. They are used to store
    arbitrary files that are not part of the main data collection process.

    These files might include datasheets, images, or other documentation.

    Files are stored in an AWS S3 bucket.
    """
    permission_classes = [DRYPermissions]
    filter_backends = [ResourceFilterBackend]
    queryset = ArbitraryFile.objects.all().order_by('-id')
    search_fields = ['@name', '@description']
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']

    def get_parsers(self):
        if self.request is not None and self.action_map[self.request.method.lower()] == 'create':
            return [MultiPartParser(), FormParser()]
        return super().get_parsers()

    def get_serializer_class(self):
        if self.action is not None and self.action == 'create':
            return ArbitraryFileCreateSerializer
        return ArbitraryFileSerializer


class _StorageTypeMixin:
    view_prefix = None
    model = None


@extend_schema_view(
    list=extend_schema(
        summary="View Galv storage by Lab",
        description="""
Galv storage is divided by Lab. Each Lab has some storage allocated for saving data.

Additional storage can be configured by connecting a new S3 bucket to your Lab.
        """
    ),
    retrieve=extend_schema(
        summary="View a Lab's storage",
        description="""
Galv storage is divided by Lab. Each Lab has some storage allocated for saving data.

Additional storage can be configured by connecting a new S3 bucket to your Lab.
        """
    ),
    partial_update=extend_schema(
        summary="Update a Lab's storage",
        description="""
Galv storage is divided by Lab. Each Lab has some storage allocated for saving data.

Additional storage can be configured by connecting a new S3 bucket to your Lab.
        """
    ),
)
class GalvStorageTypeViewSet(viewsets.ModelViewSet, _StorageTypeMixin):
    """
    GalvStorageTypes are used to describe the storage available to a Lab.
    """
    view_prefix = r'galvstoragetype'
    model = GalvStorageType
    permission_classes = [DRYPermissions]
    filter_backends = [LabResourceFilterBackend]
    serializer_class = GalvStorageTypeSerializer
    queryset = GalvStorageType.objects.all().order_by('-id')
    http_method_names = ['get', 'patch', 'options']


@extend_schema_view(
    list=extend_schema(
        summary="View Additional S3 storage by Lab",
        description="""
Additional S3 storage is storage that is configured and managed outside of Galv.
        
When the settings are configured appropriately, Galv can store data in the S3 bucket.
        
You can set a quota for the amount of data that can be stored in the bucket
so that Galv does not exceed the storage limits.
        """
    ),
    retrieve=extend_schema(
        summary="View a Lab's Additional S3 storage",
        description="""
Additional S3 storage is storage that is configured and managed outside of Galv.
        
When the settings are configured appropriately, Galv can store data in the S3 bucket.
        """
    ),
    create=extend_schema(
        summary="Create Additional S3 storage",
        description="""
Create a new S3 bucket for Galv to use.
        
When the settings are configured appropriately, Galv can store data in the S3 bucket.
        """
    ),
    partial_update=extend_schema(
        summary="Update Additional S3 storage",
        description="""
Update the settings for an S3 bucket.
        
When the settings are configured appropriately, Galv can store data in the S3 bucket.
        """
    ),
    destroy=extend_schema(
        summary="Delete Additional S3 storage",
        description="""
Delete an S3 bucket from Galv.

Deleting a bucket will cause all associated data files to be inaccessible.
Use this option with caution, and consider setting the storage to enabled=False (read-only access) instead.
        """
    )
)
class AdditionalS3StorageTypeViewSet(viewsets.ModelViewSet, _StorageTypeMixin):
    """
    AdditionalS3Storage is used to describe the storage available to a Lab.
    """
    view_prefix = r'additionals3storagetype'
    model = AdditionalS3StorageType
    permission_classes = [DRYPermissions]
    filter_backends = [LabResourceFilterBackend]
    serializer_class = AdditionalS3StorageTypeSerializer
    queryset = AdditionalS3StorageType.objects.all().order_by('-id')
    http_method_names = ['get', 'post', 'patch', 'delete', 'options']


def get_storage_url(model, view_suffix, *args, **kwargs):
    """
    Retrieve the URL for a storage type. Args and kwargs are passed to the DRF reverse function.
    """
    all_storage_views = _StorageTypeMixin.__subclasses__()
    for view in all_storage_views:
        if view.model == model:
            return reverse(f"{view.view_prefix}-{view_suffix}", *args, **kwargs)
    raise ValueError(f"Model {model} not found in storage views")
