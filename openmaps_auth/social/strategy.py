import logging

from django.conf import settings
from django.urls import reverse
from social_core.utils import is_url
from social_django.strategy import DjangoStrategy


logger = logging.getLogger(__name__)


class OpenMapsStrategy(DjangoStrategy):
    def build_absolute_uri(self, path=None):
        if is_url(settings.CALLBACK_URL):
            callback_path = settings.CALLBACK_URL
        else:
            callback_path = reverse(settings.CALLBACK_URL)
        if self.request:
            uri = self.request.build_absolute_uri(callback_path)
        else:
            uri = callback_path
        logger.debug(f"build_absolute_uri: {uri}")
        return uri
