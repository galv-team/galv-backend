from django.db import models
from django.db.models.fields.files import FieldFile
from rest_framework.reverse import reverse

from .storages import MediaStorage, LocalDataStorage


class DynamicStorageFieldFile(FieldFile):
    def __init__(self, instance, field, name):
        super(DynamicStorageFieldFile, self).__init__(instance, field, name)
        self.storage = field.storage

    def update_acl(self):
        if not self:
            return
        # Only close the file if it's already open, which we know by
        # the presence of self._file
        if hasattr(self, '_file'):
            self.close()  # This update_acl method we have already defined in UpdateACLMixin class
        if isinstance(self.storage, MediaStorage):
            self.storage.update_acl(self.name)

#
class DynamicStorageFileField(models.FileField):
    attr_class = DynamicStorageFieldFile

    def pre_save(self, model_instance, add):
        if model_instance.is_public:
            self.storage.default_acl = "public-read"
            self.storage.querystring_auth = False
        else:
            self.storage.default_acl = "private"
            self.storage.querystring_auth = True

        file = super(DynamicStorageFileField, self).pre_save(model_instance, add)

        if file and file._committed:
            # This update_acl method we have already defined
            # in DynamicStorageFieldFile class above.
            file.update_acl()
        return file


class LabDependentStorageFieldFile(FieldFile):
    """
    A custom FieldFile that allows the storage to be set dynamically based on the model instance.
    """
    def __init__(self, instance, field, name):
        super().__init__(instance, field, name)
        self.storage = instance.get_storage()

    def __iter__(self):
        if self:
            yield super().__iter__()

    @property
    def url(self):
        if not self.instance:
            return None
        return reverse(self.instance.view_name, args=[self.instance.pk])

    def backend_url(self):
        """
        Returns the backend URL for the file.

        Not a property because it takes a long time to run.
        """
        return super().url


class LabDependentStorageFileField(models.FileField):
    """
    A custom FileField that allows the storage to be set dynamically based on the model instance.
    The storage argument should be a function that returns a dummy storage class instance
     unless provided with a model instance.
    """
    attr_class = LabDependentStorageFieldFile

    def pre_save(self, model_instance, add):
        self.storage = model_instance.get_storage(True)
        return super().pre_save(model_instance, add)
