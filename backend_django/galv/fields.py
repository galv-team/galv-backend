from django.db import models
from django.db.models.fields.files import FieldFile

from .storages import PrivateImageStorage, PublicImageStorage

class DynamicStorageFieldFile(FieldFile):
    def __init__(self, instance, field, name):
        super(DynamicStorageFieldFile, self).__init__(instance, field, name)
        if instance.is_public:
            self.storage = PublicImageStorage()
        else:
            self.storage = PrivateImageStorage()

    def update_acl(self):
        if not self:
            return
        # Only close the file if it's already open, which we know by
        # the presence of self._file
        if hasattr(self, '_file'):
            self.close()  # This update_acl method we have already defined in UpdateACLMixin class
        self.storage.update_acl(self.name)


class DynamicStorageFileField(models.FileField):
    attr_class = DynamicStorageFieldFile

    def pre_save(self, model_instance, add):
        if model_instance.is_public:
            storage = PublicImageStorage()
        else:
            storage = PrivateImageStorage()
        self.storage = storage

        file = super(DynamicStorageFileField, self).pre_save(model_instance, add)

        if file and file._committed:
            # This update_acl method we have already defined
            # in DynamicStorageFieldFile class above.
            file.update_acl()
        return file
