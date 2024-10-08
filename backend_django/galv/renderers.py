# https://www.django-rest-framework.org/api-guide/renderers/#setting-the-character-set
from rest_framework import renderers


class BinaryRenderer(renderers.BaseRenderer):
    media_type = "application/octet-stream"
    charset = "utf-8"
    format = "json"

    def render(self, data, media_type=None, renderer_context=None):
        return data
