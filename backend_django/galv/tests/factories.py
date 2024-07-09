# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

import os
from functools import partial

import factory
from django.core.files.uploadedfile import SimpleUploadedFile
from factory.base import StubObject
import faker
import django.conf.global_settings

from ..models import EquipmentFamily, Harvester, \
    MonitoredPath, \
    ObservedFile, \
    Cell, \
    CellFamily, \
    Equipment, ScheduleFamily, Schedule, CyclerTest, \
    ScheduleIdentifiers, CellFormFactors, CellChemistries, CellManufacturers, \
    CellModels, EquipmentManufacturers, EquipmentModels, EquipmentTypes, Experiment, \
    ValidationSchema, GroupProxy, UserProxy, Lab, Team, AutoCompleteEntry, DataUnit, DataColumnType, ParquetPartition, \
    ColumnMapping, GalvStorageType, AdditionalS3StorageType, ArbitraryFile
from ..models.choices import UserLevel

fake = faker.Faker(django.conf.global_settings.LANGUAGE_CODE)


class DjangoModelFactory(factory.django.DjangoModelFactory):
    """
    A factory for Django models that uses the `django.db.models.Model` class.
    This model will handle IntegrityErrors when trying to create an object that already exists.
    """
    def create(self, *args, **kwargs):
        try:
            with transaction.atomic():
                return super().create(*args, **kwargs)
        except IntegrityError:
            id = self._meta.model.objects.count() + 100
            return super().create(*args, **kwargs, pk=id)


def to_type_value_notation(obj):
    if isinstance(obj, dict):
        return {"_type": "object", "_value": {k: to_type_value_notation(v) for k, v in obj.items()}}
    elif isinstance(obj, list):
        return {"_type": "array", "_value": [to_type_value_notation(v) for v in obj]}
    return {'_type': type(obj).__name__, '_value': obj}

def fix_custom_properties(obj):
    without_dec_keys = {k: v for k, v in obj.ap.items() if k not in obj._Resolver__declarations.declarations.keys()}
    # Adapt to {_type: 'type', _value: value} format
    return {k: to_type_value_notation(v) for k, v in without_dec_keys.items()}

def make_tmp_file():
    length = fake.pyint(min_value=1, max_value=1000000)
    content = fake.binary(length=length)
    file = SimpleUploadedFile(
        name=f"{fake.word()}_{fake.file_name(extension='tst')}",
        content=content,
        content_type=fake.mime_type()
    )
    return file

class ByValueMixin:
    value = None

class EquipmentTypesFactory(DjangoModelFactory):
    class Meta:
        model = EquipmentTypes
        django_get_or_create = ('value',)
    value = factory.Faker('bs')
class EquipmentModelsFactory(DjangoModelFactory):
    class Meta:
        model = EquipmentModels
        django_get_or_create = ('value',)
    value = factory.Faker('catch_phrase')
class EquipmentManufacturersFactory(DjangoModelFactory):
    class Meta:
        model = EquipmentManufacturers
        django_get_or_create = ('value',)
    value = factory.Faker('company')
class CellModelsFactory(DjangoModelFactory):
    class Meta:
        model = CellModels
        django_get_or_create = ('value',)
    value = factory.Faker('catch_phrase')
class CellManufacturersFactory(DjangoModelFactory):
    class Meta:
        model = CellManufacturers
        django_get_or_create = ('value',)
    value = factory.Faker('company')
class CellChemistriesFactory(DjangoModelFactory):
    class Meta:
        model = CellChemistries
        django_get_or_create = ('value',)
    value = factory.Faker('catch_phrase')
class CellFormFactorsFactory(DjangoModelFactory):
    class Meta:
        model = CellFormFactors
        django_get_or_create = ('value',)
    value = factory.Faker('bs')
class ScheduleIdentifiersFactory(DjangoModelFactory):
    class Meta:
        model = ScheduleIdentifiers
        django_get_or_create = ('value',)
    value = factory.Faker('bs')

def generate_create_dict(root_factory: factory.django.DjangoModelFactory):
    def stub_to_entry(stub, **kwargs):
        try:
            obj = stub.factory_wrapper.factory._meta.model.objects.get(**kwargs)
        except (
                stub.factory_wrapper.factory._meta.model.DoesNotExist,
                stub.factory_wrapper.factory._meta.model.MultipleObjectsReturned
        ):
            obj = stub.factory_wrapper.factory.create(**kwargs)
        # Check for autocomplete entries
        if isinstance(obj, AutoCompleteEntry):
            return obj.value
        else:
            return obj.pk

    def dict_factory(client_factory, **kwargs):
        dict = client_factory.stub(**kwargs).__dict__
        # Create children
        for key, value in client_factory._meta.declarations.items():
            if isinstance(value, factory.SubFactory):
                dict[key] = stub_to_entry(value, **kwargs.pop(key, {}))
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], factory.SubFactory):
                child_kwargs = kwargs.pop(key, {})
                dict[key] = [stub_to_entry(v, **child_kwargs) for v in value]
        return dict

    return partial(dict_factory, root_factory)


class UserFactory(DjangoModelFactory):
    class Meta:
        model = UserProxy
        django_get_or_create = ('username',)

    username = factory.Faker('user_name')


class GroupFactory(DjangoModelFactory):
    class Meta:
        model = GroupProxy
        django_get_or_create = ('name',)
        exclude = ('n',)

    n = factory.Faker('random_int', min=1, max=100000)
    name = factory.LazyAttribute(lambda x: f"group_{x.n}")


class GalvStorageTypeFactory(DjangoModelFactory):
    class Meta:
        model = GalvStorageType
        django_get_or_create = ('lab',)
    priority = 0
    quota_bytes = 1_000_0000


class AdditionalS3StorageTypeFactory(DjangoModelFactory):
    class Meta:
        model = AdditionalS3StorageType
        django_get_or_create = ('lab', 'priority',)
    priority = factory.Faker('pyint', min_value=5, max_value=1500)
    quota_bytes = 1_000_0000
    bucket_name = factory.Faker('word')
    location = factory.Faker('word')
    access_key = factory.Faker('word')
    secret_key = factory.Faker('word')


class LabFactory(DjangoModelFactory):
    class Meta:
        model = Lab
        django_get_or_create = ('name',)

    name = factory.Faker('company')

    @factory.post_generation
    def local_storage_quota_bytes(self, create, *_args, **_kwargs):
        if not create:
            return
        if GalvStorageType.objects.filter(lab=self).count() == 0:
            GalvStorageTypeFactory.create(lab=self)


class TeamFactory(DjangoModelFactory):
    class Meta:
        model = Team
        django_get_or_create = ('name', 'lab',)

    name = factory.Faker('company')
    lab = factory.SubFactory(LabFactory)


class HarvesterFactory(DjangoModelFactory):
    class Meta:
        model = Harvester
        django_get_or_create = ('name', 'lab',)
        exclude = ('first_name',)

    first_name = fake.unique.first_name()
    name = factory.LazyAttribute(lambda x: f"Harvester {x.first_name}")
    lab = factory.SubFactory(LabFactory)


class MonitoredPathFactory(DjangoModelFactory):
    class Meta:
        model = MonitoredPath
        django_get_or_create = ('path', 'harvester',)

    team = factory.SubFactory(TeamFactory)
    path = factory.LazyAttribute(lambda x: os.path.dirname(fake.file_path(absolute=False, depth=2)))
    regex = ".*"
    harvester = factory.SubFactory(HarvesterFactory)
    edit_access_level = UserLevel.TEAM_MEMBER.value
    delete_access_level = UserLevel.TEAM_MEMBER.value


class ColumnMappingFactory(DjangoModelFactory):
    class Meta:
        model = ColumnMapping
        django_get_or_create = ('name',)

    name = factory.Faker('word')
    map = dict()
    read_access_level = UserLevel.TEAM_MEMBER.value
    edit_access_level = UserLevel.TEAM_MEMBER.value
    delete_access_level = UserLevel.TEAM_MEMBER.value


class ObservedFileFactory(DjangoModelFactory):
    class Meta:
        model = ObservedFile
        django_get_or_create = ('harvester', 'path')
        exclude = ('path_root',)

    @staticmethod
    def path_with_root(instance):
        return os.path.join(instance.path_root, fake.file_path(depth=fake.random_digit_not_null(), absolute=False))

    path_root = factory.Faker('file_path', depth=1, absolute=True)
    path = factory.LazyAttribute(path_with_root)
    harvester = factory.SubFactory(HarvesterFactory)
    mapping = factory.SubFactory(ColumnMappingFactory)
    storage_type = factory.SubFactory(GalvStorageTypeFactory, lab=factory.SelfAttribute('..harvester.lab'))


class ParquetPartitionFactory(DjangoModelFactory):
    class Meta:
        model = ParquetPartition
        django_get_or_create = ('observed_file', 'partition_number')

    observed_file = factory.SubFactory(ObservedFileFactory)
    partition_number = factory.Faker('random_int', min=1, max=1000000)
    storage_type = factory.SubFactory(
        GalvStorageTypeFactory,
        lab=factory.SelfAttribute('..observed_file.harvester.lab')
    )


class CellFamilyFactory(DjangoModelFactory):
    class Meta:
        model = CellFamily
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    manufacturer = factory.SubFactory(CellManufacturersFactory)
    model = factory.SubFactory(CellModelsFactory)
    form_factor = factory.SubFactory(CellFormFactorsFactory)
    datasheet = factory.Faker('uri')
    chemistry = factory.SubFactory(CellChemistriesFactory)
    nominal_voltage_v = factory.Faker('pyfloat', min_value=1.0, max_value=1000000.0)
    nominal_capacity_ah = factory.Faker('pyfloat', min_value=1.0, max_value=1000000.0)
    initial_ac_impedance_o = factory.Faker('pyfloat', min_value=1.0, max_value=1000000.0)
    initial_dc_resistance_o = factory.Faker('pyfloat', min_value=1.0, max_value=1000000.0)
    energy_density_wh_per_kg = factory.Faker('pyfloat', min_value=1.0, max_value=1000000.0)
    power_density_w_per_kg = factory.Faker('pyfloat', min_value=1.0, max_value=1000000.0)


class CellFactory(DjangoModelFactory):
    class Meta:
        model = Cell
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    identifier = factory.Faker('bothify', text='?????-##??#-#?#??-?####-?#???')
    family = factory.SubFactory(CellFamilyFactory)


class EquipmentFamilyFactory(DjangoModelFactory):
    class Meta:
        model = EquipmentFamily
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    type = factory.SubFactory(EquipmentTypesFactory)
    manufacturer = factory.SubFactory(EquipmentManufacturersFactory)
    model = factory.SubFactory(EquipmentModelsFactory)


class EquipmentFactory(DjangoModelFactory):
    class Meta:
        model = Equipment
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    identifier = factory.Faker('bothify', text='?????-##??#-#?#??-?####-?#???')
    family = factory.SubFactory(EquipmentFamilyFactory)
    calibration_date = factory.Faker('date')


class ScheduleFamilyFactory(DjangoModelFactory):
    class Meta:
        model = ScheduleFamily
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    identifier = factory.SubFactory(ScheduleIdentifiersFactory)
    description = factory.Faker('sentence')
    ambient_temperature_c = factory.Faker('pyfloat', min_value=0.0, max_value=1000.0)
    pybamm_template = None


class ScheduleFactory(DjangoModelFactory):
    class Meta:
        model = Schedule

    # Don't test Schedule custom_properties because we can't use JSON format to upload files
    team = factory.SubFactory(TeamFactory)
    family = factory.SubFactory(ScheduleFamilyFactory)
    schedule_file = factory.LazyFunction(make_tmp_file)


class ArbitraryFileFactory(DjangoModelFactory):
    class Meta:
        model = ArbitraryFile
        django_get_or_create = ('name', 'team',)

    team = factory.SubFactory(TeamFactory)
    file = factory.LazyFunction(make_tmp_file)
    name = factory.Faker('pystr')
    description = factory.Faker('sentence')

    @factory.post_generation
    def add_storage_type(self, create, extracted, **kwargs):
        if not create:
            return
        if not extracted:
            extracted = GalvStorageTypeFactory.create(lab=self.team.lab)
        self.storage_type = extracted


class CyclerTestFactory(DjangoModelFactory):
    class Meta:
        model = CyclerTest
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    cell = factory.SubFactory(CellFactory, team=team)
    schedule = factory.SubFactory(ScheduleFactory, team=team)

    @factory.post_generation
    def equipment(self, create, extracted, **kwargs):
        if not create or not extracted:
            # Stub build - horrible hack to create child objects and return ids
            # We _really_ shouldn't be creating children from a parent stub call, but we are.
            if isinstance(self, StubObject):
                equipment = [EquipmentFactory.create(**kwargs) for _ in range(3)]
                self.equipment = [e.pk for e in equipment]
            # Simple build, or nothing to add, do nothing.
            return

        # Add the iterable of equipment using bulk addition
        self.equipment.add(*extracted)

    @factory.post_generation
    def files(self, create, extracted, **kwargs):
        if not create or not extracted:
            # Stub build - horrible hack to create child objects and return ids
            # We _really_ shouldn't be creating children from a parent stub call, but we are.
            if isinstance(self, StubObject):
                files = [ObservedFileFactory.create(**kwargs) for _ in range(3)]
                self.files = [e.pk for e in files]
            # Simple build, or nothing to add, do nothing.
            return

        # Add the iterable of equipment using bulk addition
        self.files.add(*extracted)


class ExperimentFactory(DjangoModelFactory):
    class Meta:
        model = Experiment
        exclude = ('ap',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    title = factory.Faker('sentence')
    description = factory.Faker('sentence')

    @factory.post_generation
    def cycler_tests(self, create, extracted, **kwargs):
        if not create:
            if isinstance(self, StubObject):
                cycler_tests = [CyclerTestFactory.create(**kwargs) for _ in range(3)]
                self.cycler_tests = [c.pk for c in cycler_tests]
            # Simple build, or nothing to add, do nothing.
            return
        if not extracted:
            extracted = [CyclerTestFactory() for _ in range(3)]
        # Add the iterable of cycler tests using bulk addition
        self.cycler_tests.add(*extracted)

    @factory.post_generation
    def authors(self, create, extracted, **kwargs):
        if not create:
            if isinstance(self, StubObject):
                authors = [UserFactory.create(**kwargs) for _ in range(3)]
                self.authors = [a.pk for a in authors]
            # Simple build, or nothing to add, do nothing.
            return
        if not extracted:
            extracted = [UserFactory() for _ in range(3)]
        # Add the iterable of cycler tests using bulk addition
        self.authors.add(*extracted)

class DataUnitFactory(DjangoModelFactory):
    class Meta:
        model = DataUnit

    team = factory.SubFactory(TeamFactory)
    name = factory.Faker('word')
    description = factory.Faker('sentence')
    symbol = factory.Faker('pystr', max_chars = 3)
    is_default = False

class DataColumnTypeFactory(DjangoModelFactory):
    class Meta:
        model = DataColumnType

    team = factory.SubFactory(TeamFactory)
    unit = factory.SubFactory(DataUnitFactory)
    name = factory.Faker('word')
    description = factory.Faker('sentence')
    is_default = False
    is_required = False

def to_validation_schema(obj):
    # Suppress errors when 'not' is a key
    obj = {f"x{k}": v for k, v in obj.items()}
    return {'$id': 'abc', '$defs': {}, **obj}

class ValidationSchemaFactory(DjangoModelFactory):
    class Meta:
        model = ValidationSchema
        exclude = ('ap', 's',)

    ap = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    custom_properties = factory.LazyAttribute(fix_custom_properties)
    team = factory.SubFactory(TeamFactory)
    name = factory.Faker('sentence')
    s = factory.Faker('pydict', value_types=['str', 'int', 'float', 'dict', 'list'])
    schema = factory.LazyAttribute(lambda s: to_validation_schema(s.s))
