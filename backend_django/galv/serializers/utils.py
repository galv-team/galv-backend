import json
from collections import OrderedDict

import django.db.models
from django.core.serializers.json import DjangoJSONEncoder
from drf_spectacular.utils import extend_schema_field
from dry_rest_permissions.generics import DRYPermissionsField
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.core.exceptions import ValidationError as DjangoValidationError

from galv.models import ValidationSchema, GroupProxy, UserProxy, VALIDATION_MOCK_ENDPOINT
from rest_framework.fields import DictField


url_help_text = "Canonical URL for this object"

OUTPUT_STYLE_FLAT = 'flat'
OUTPUT_STYLE_CONTEXT = 'context'

def get_output_style(request):
    if request.path == VALIDATION_MOCK_ENDPOINT:
        return OUTPUT_STYLE_FLAT
    if request.query_params.get('style') in [OUTPUT_STYLE_FLAT, OUTPUT_STYLE_CONTEXT]:
        return request.query_params['style']
    if 'html' in request.accepted_media_type or request.query_params.get('format') == 'html':
        return OUTPUT_STYLE_CONTEXT
    return OUTPUT_STYLE_FLAT

def serializer_class_from_string(class_name: str):
    """
    Get a class from a string.
    """
    if class_name not in [
        'UserSerializer', 'TransparentGroupSerializer', 'LabSerializer', 'TeamSerializer', 'HarvesterSerializer',
        'HarvestErrorSerializer', 'MonitoredPathSerializer', 'ObservedFileSerializer', 'DataColumnSerializer',
        'DataColumnTypeSerializer', 'DataUnitSerializer', 'CellFamilySerializer', 'CellSerializer',
        'EquipmentFamilySerializer', 'EquipmentSerializer', 'ScheduleFamilySerializer', 'ScheduleSerializer',
        'CyclerTestSerializer', 'ExperimentSerializer', 'ValidationSchemaSerializer', 'EquipmentTypesSerializer',
        'EquipmentModelsSerializer', 'EquipmentManufacturersSerializer', 'CellModelsSerializer',
        'CellManufacturersSerializer', 'CellChemistriesSerializer', 'CellFormFactorsSerializer',
        'ScheduleIdentifiersSerializer', 'ParquetPartitionSerializer', 'ArbitraryFileSerializer',
        'ColumnMappingSerializer'
    ]:
        raise ValueError(f"serializer_class_from_string will only retrieve custom Serializers, not {class_name}")
    s = __import__('galv.serializers', fromlist=[class_name])
    return getattr(s, class_name)

class CreateOnlyMixin(serializers.ModelSerializer):
    """
    A Serializer that supports create_only fields.
    create_only fields will be marked as 'read_only' if the view.action is not 'create'.
    Otherwise, they will retain their original keywords such as 'required' and 'allow_null'.
    """
    def get_extra_kwargs(self):
        extra_kwargs_for_edit = super().get_extra_kwargs()
        if "view" not in self.context or self.context['view'].action != 'create':
            for field_name in extra_kwargs_for_edit:
                kwargs = extra_kwargs_for_edit.get(field_name, {})
                kwargs['read_only'] = True
                extra_kwargs_for_edit[field_name] = kwargs

        return extra_kwargs_for_edit


def augment_extra_kwargs(extra_kwargs: dict[str, dict] = None):
    def _augment(name: str, content: dict):
        if name == 'url':
            return {'help_text': url_help_text, 'read_only': True, **content}
        if name == 'id':
            return {'help_text': "Auto-assigned object identifier", 'read_only': True, **content}
        return {**content}

    if extra_kwargs is None:
        extra_kwargs = {}
    extra_kwargs = {'url': {}, 'id': {}, **extra_kwargs}
    return {k: _augment(k, v) for k, v in extra_kwargs.items()}


def get_model_field(model: django.db.models.Model, field_name: str) -> django.db.models.Field:
    """
    Get a field from a Model.
    Works, but generates type warnings because Django uses hidden Metaclass ModelBase for models.
    """
    fields = {f.name: f for f in model._meta.fields}
    return fields[field_name]


class GetOrCreateTextSerializer(serializers.HyperlinkedModelSerializer):
    """
    Expose a full AutoCompleteEntry model.
    """
    def __init__(self, model):
        super().__init__()
        self.Meta.model = model

    class Meta:
        model = None
        fields = ['url', 'id', 'value', 'ld_value']


class GetOrCreateTextStringSerializer(serializers.ModelSerializer):
    """
    For use with AutoCompleteEntry models: Simply returns the value field. Read-only.
    """
    def to_representation(self, instance):
        if get_output_style(self.context['request']) != OUTPUT_STYLE_CONTEXT:
            return super().to_representation(instance)
        return instance.value

    def to_internal_value(self, data):
        raise RuntimeError("GetOrCreateTextStringSerializer is read-only")

    class Meta:
        fields = '__all__'

def get_GetOrCreateTextStringSerializer(django_model):
    """
    Return a concrete child class for GetOrCreateTextStringSerializer linking it to a model.
    """
    return type(
        f"{django_model.__name__}TextSerializer",
        (GetOrCreateTextStringSerializer,),
        {
            'Meta': type('Meta', (GetOrCreateTextStringSerializer.Meta,), {'model': django_model})
        })

class GetOrCreateTextField(serializers.CharField):
    """
    A CharField that will create a new object if it does not exist.
    Objects are created with the value of the CharField in the table specified by `foreign_model`.

    The model field must be a ForeignKey to the table specified by `foreign_model`,
    and the latter will typically be an AutoCompleteEntry model.

    If the table uses a different field name for the value, specify it with `foreign_model_field`.
    """
    def __init__(self, foreign_model, foreign_model_field: str = 'value', **kwargs):
        super().__init__(**kwargs)
        self.foreign_model = foreign_model
        self.foreign_model_field = foreign_model_field

    def to_internal_value(self, data):
        # Let CharField do the basic validation
        data = super().to_internal_value(data)
        return self.foreign_model.objects.get_or_create(**{self.foreign_model_field: data})[0]
    def to_representation(self, value):
        return getattr(value, self.foreign_model_field)


class GetOrCreateTextFieldList(serializers.ListField):
    """
    Adaptation of serializers.ListField to use GetOrCreateTextField.
    Solves 'ManyRelatedManager is not iterable' error.

    Use to support ManyToMany relationships with AutoCompleteEntry models.
    """
    def to_representation(self, data):
        return super().to_representation(data.all())


class CustomPropertiesModelSerializer(serializers.HyperlinkedModelSerializer):
    """
    A ModelSerializer that maps unrecognised properties in the input to an 'custom_properties' JSONField,
    and unpacks the 'custom_properties' JSONField into the output.

    The Meta.model must have a custom_properties JSONField.
    """
    class Meta:
        model: django.db.models.Model
        include_custom_properties = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        model_fields = {f.name for f in self.Meta.model._meta.fields}
        if 'custom_properties' not in model_fields:
            raise ValueError("CustomPropertiesModelSerializer must define custom_properties")


@extend_schema_field({
        'type': 'object',
        'properties': {
            'read': {'type': 'boolean'},
            'write': {'type': 'boolean'},
            'create': {'type': 'boolean'},
        }
    })
class DRYPermissionsFieldWrapper(DRYPermissionsField):
    pass

class PermissionsMixin(serializers.Serializer):
    permissions: DictField = DRYPermissionsFieldWrapper()


class GroupProxyField(serializers.Field):
    """
    Fetch proxied User/Group objects.
    """
    def to_internal_value(self, data):
        target = super().to_internal_value(data)
        target.__class__ = GroupProxy
        return target

class UserProxyField(serializers.Field):
    """
    Fetch proxied User/Group objects.
    """
    def to_internal_value(self, data):
        target = super().to_internal_value(data)
        target.__class__ = UserProxy
        return target


class HyperlinkedRelatedIdField(serializers.HyperlinkedRelatedField):
    """
    A HyperlinkedRelatedField that can be written to more flexibly.
    Lookup priority is, in order:
    A string or integer primary key value
    An object with a 'pk' or 'id' property
    An object with a 'url' property
    A URL string
    """
    def to_internal_value(self, data):
        if isinstance(data, dict):
            if 'pk' in data:
                data = data['pk']
            elif 'id' in data:
                data = data['id']
            elif 'url' in data:
                data = data['url']
            else:
                raise ValidationError("Object must have a 'pk', 'id', or 'url' property")
        elif isinstance(data, str):
            # Try to parse as an integer, but don't fail if it's not because uuids are stringy
            try:
                data = int(data)
            except ValueError:
                pass
        try:
            return self.get_queryset().get(pk=data)
        except (TypeError, ValueError, DjangoValidationError, self.queryset.model.DoesNotExist):
            return super().to_internal_value(data)

    def to_representation(self, value):
        return super().to_representation(value)

class GroupHyperlinkedRelatedIdListField(HyperlinkedRelatedIdField, GroupProxyField):
    pass

class UserHyperlinkedRelatedIdListField(HyperlinkedRelatedIdField, UserProxyField):
    pass

class TruncatedHyperlinkedRelatedIdField(HyperlinkedRelatedIdField):
    """
    A HyperlinkedRelatedField that reads as a truncated representation of the target object,
    and writes as the target object's URL.

    The 'url' and 'id' fields are always included.
    Other fields are specified by the 'fields' argument to the constructor.
    """
    def __init__(self, child_serializer_class, fields, *args, **kwargs):
        self.child_serializer_class = child_serializer_class
        if isinstance(fields, str):
            fields = [fields]
        if not isinstance(fields, list):
            raise ValueError("fields must be a list")
        self.child_fields = fields
        # Support create_only=True by removing queryset and applying read_only=True
        self.create_only = kwargs.pop('create_only', False)
        super().__init__(*args, **kwargs)

    def bind(self, field_name, parent):
        super().bind(field_name, parent)
        if self.create_only and 'view' in self.context and self.context['view'].action != 'create':
            self.read_only = True
            self.queryset = None

    def to_representation(self, instance):
        try:
            if get_output_style(self.context['request']) != OUTPUT_STYLE_CONTEXT:
                return super().to_representation(instance)
        except (AttributeError, KeyError):
            pass
        if isinstance(self.child_serializer_class, str):
            child = serializer_class_from_string(self.child_serializer_class)
            self.child_serializer_class = child  # cache result
        else:
            child = self.child_serializer_class
        fields = list({
            *[f for f in self.child_serializer_class.Meta.fields if f in ['url', 'id']],# 'permissions']],
            *self.child_fields
        })

        class TruncatedSerializer(child):
            def __init__(self, obj, include_fields, *args, **kwargs):
                self.Meta.fields = include_fields
                self.Meta.read_only_fields = include_fields
                super().__init__(obj, *args, **kwargs)
            class Meta(child.Meta):
                include_custom_properties = False
                include_validation = False

        serializer = TruncatedSerializer(instance, fields, context=self.context)
        return serializer.data

    def get_choices(self, cutoff=None):
        queryset = self.get_queryset()
        if queryset is None:
            # Ensure that field.choices returns something sensible
            # even when accessed with a read-only field.
            return {}

        if cutoff is not None:
            queryset = queryset[:cutoff]

        return OrderedDict([
            (
                item.pk,
                self.display_value(item)
            )
            for item in queryset
        ])

    def use_pk_only_optimization(self):
        return False


class TruncatedGroupHyperlinkedRelatedIdField(TruncatedHyperlinkedRelatedIdField, GroupProxyField):
    def to_representation(self, instance):
        instance.__class__ = GroupProxy
        return super().to_representation(instance)

class TruncatedUserHyperlinkedRelatedIdField(TruncatedHyperlinkedRelatedIdField, UserProxyField):
    def to_representation(self, instance):
        instance.__class__ = UserProxy
        return super().to_representation(instance)


class ValidationPresentationMixin(serializers.Serializer):
    """
    Resources with families perform inline expansion of family properties during validation.
    """
    def to_representation(self, instance):
        try:
            if self.context['request'].path == VALIDATION_MOCK_ENDPOINT and hasattr(instance, 'family'):
                representation = super().to_representation(instance)
                family_serializer = self.fields['family'].child_serializer_class
                if isinstance(family_serializer, str):
                    family_serializer = serializer_class_from_string(family_serializer)
                representation.pop('family')
                return {**family_serializer(instance.family, context=self.context).data, **representation}
        except Exception as e:
            print(e)
            pass
        return super().to_representation(instance)


class PasswordField(serializers.CharField):
    """
    A CharField that will hash the input value.
    """
    def __init__(self, show_first_chars=0, min_length=10, **kwargs):
        super().__init__(**kwargs)
        self.show_first_chars = show_first_chars
        self.min_length = min_length

    def to_internal_value(self, data):
        return super().to_internal_value(data)

    def to_representation(self, value):
        v = super().to_representation(value)
        if v is None:
            return None
        stars = '*' * max(max(self.min_length, 1), len(v))
        if self.show_first_chars:
            return f"{v[:self.show_first_chars]}{stars[self.show_first_chars:]}"
        return stars


class DumpSerializer(serializers.Serializer):
    """
    A Serializer that will dump a model to a JSON dictionary of id: properties.
    Related fields are included in the dictionary, and the process is repeated for them.

    Models will not be dumped if they do not have a special_dump_fields property.
    Fields can be excluded from the dump by setting special_dump_fields = {'field_name': X, ...}.
    X can be a callable that returns a value, or a value to be used directly.
    If X is None, or a callable that returns None, the field will be excluded from the dump.
    X as a callable will be called with the arguments:
        - putative value of the field
        - the model instance
        - whether the model instance is the root of the dump
        - this serializer instance in case you need to continue dumping with self.dump_value(), check the request, etc.
    Set special_dump_fields to {} to dump all fields.
    As a convenience, special_dump_fields can be a set of field names, which will be converted to a dictionary
    with all values set to None.
    special_dump_fields will cascade to parent models, so if a parent model has a special_dump_fields property,
    it will apply to child models that do not have their own special_dump_fields property.

    Models that do not have special_dump_fields will be represented by the output of their
    .__dump__() method if it exists, or by their __str__() method if it does not.

    __dump__() output will be coerced to a str value, because the output is used as a dictionary key.
    The output should not be sensitive information, because it will be exposed where relevant,
    even if the user does not have permission to read the whole object.

    A model that does not allow read permissions will be redacted.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # if not self.context or 'request' not in self.context:
        #     raise ValueError("DumpSerializer requires a 'request' in the context")
        self.request = self.context.get('request')
        self.dump = {}

    @property
    def dumped_object_ids(self):
        return self.dump.keys()

    def dump_ref_or_str(self, model):
        """
        Return the id of the model if it has been dumped, or its string representation.
        This can be used in lambda callbacks to avoid crawling huge swathes of the database
        when e.g. a Cell calls a Cell Family which then wants to dump all its Cells.
        """
        id = str(model.pk)
        if id in self.dumped_object_ids:
            return id
        return self.model_dump_value(model)

    @staticmethod
    def special_dump_fields(obj):
        if hasattr(obj, 'special_dump_fields'):
            if isinstance(obj.special_dump_fields, set):
                return [{k: None} for k in obj.special_dump_fields]
            if not isinstance(obj.special_dump_fields, dict) and obj.special_dump_fields is not None:
                raise ValueError("special_dump_fields must be a dictionary")
            return obj.special_dump_fields
        return None

    @staticmethod
    def model_dump_value(model):
        if hasattr(model, '__dump__') and callable(model.__dump__):
            return str(model.__dump__())
        return str(model.pk)

    def dump_relation(self, rel, root=False):
        dump_value = self.model_dump_value(rel)
        special_fields = self.special_dump_fields(rel)

        if special_fields is None:
            return dump_value

        if dump_value not in self.dumped_object_ids:
            representation = {
                'resource_type': rel.__class__.__name__
            }
            # Check permissions
            allowed = True
            if hasattr(rel, 'has_read_permission'):
                allowed = rel.has_read_permission(self.context['request'])
                if allowed and hasattr(rel, 'has_object_read_permission'):
                    allowed = rel.has_object_read_permission(self.request)
            if not allowed:
                representation['redacted'] = True
            else:
                self.dump[dump_value] = representation  # adding to dump here to prevent infinite recursion

                for field in rel._meta.get_fields():
                    if field.name in special_fields:
                        x = special_fields[field.name]
                        if x is not None:
                            if callable(x):
                                y = x(getattr(rel, field.name), rel, root, self)
                                if y is not None:
                                    representation[field.name] = y
                            else:
                                representation[field.name] = x
                        continue

                    representation[field.name] = self.dump_value(getattr(rel, field.name))

            self.dump[dump_value] = representation  # updating with full representation

        return dump_value

    @staticmethod
    def dump_other(v):
        try:
            return json.loads(json.dumps(v, cls=DjangoJSONEncoder))
        except Exception as e:
            print(f"Couldn't serialize value for dumping:\n{e}\n{v}")
        return str(v)

    def dump_value(self, value, root=False):
        if isinstance(value, django.db.models.Model):
            return self.dump_relation(value, root)
        if isinstance(value, django.db.models.Manager):
            value = value.all()
        if isinstance(value, list) or isinstance(value, django.db.models.QuerySet):
            return [self.dump_value(o, root) for o in value]
        return self.dump_other(value)

    def to_representation(self, instance, accumulator = None, nest_level = 0):
        """
        Crawl through the object graph, dumping objects to a dictionary.
        """
        # request is required for checking permissions
        self.dump = {}

        self.dump_value(instance, root=True)
        return self.dump
