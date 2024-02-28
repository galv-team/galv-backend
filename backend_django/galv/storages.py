# SPDX-License-Identifier: BSD-2-Clause
# Copyright  (c) 2020-2023, The Chancellor, Masters and Scholars of the University
# of Oxford, and the 'Galv' Developers. All rights reserved.

# adapted from https://backendengineer.io/store-django-static-and-media-files-in-aws-s3/
from django.conf import settings
from storages.backends.s3boto3 import S3Boto3Storage
from storages.utils import clean_name

class StaticStorage(S3Boto3Storage):
    location = settings.STATICFILES_LOCATION
    default_acl = "public-read"
    querystring_auth = False


class MediaStorage(S3Boto3Storage):
    location = settings.MEDIAFILES_LOCATION
    file_overwrite = False
    querystring_auth = False

# adapted from https://medium.com/@hiteshgarg14/how-to-dynamically-select-storage-in-django-filefield-bc2e8f5883fd
class UpdateACLMixin(S3Boto3Storage):
    default_acl = "private"

    def update_acl(self, name):
        name = self._normalize_name(clean_name(name))
        self.bucket.Object(name).Acl().put(ACL=self.default_acl)


class PublicImageStorage(UpdateACLMixin, MediaStorage):
    default_acl = "public-read"
    file_overwrite = True


class PrivateImageStorage(PublicImageStorage):
    default_acl = 'private'
    file_overwrite = True
    custom_domain = False
    querystring_auth = True
