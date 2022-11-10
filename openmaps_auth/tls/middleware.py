import logging

from django.contrib.auth import authenticate, login
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.urls import reverse

from ..utils import get_index_url, set_auth_cookies


logger = logging.getLogger(__name__)


class TLSClientMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not hasattr(request, "user"):
            raise ImproperlyConfigured(
                "The TLS client middleware requires Django's"
                " authentication middleware to be installed."
            )
        if request.user.is_authenticated:
            return self.get_response(request)
        user = authenticate(request)
        if not user or not user.is_authenticated:
            return self.get_response(request)
        if request.path_info == reverse("openmaps_login"):
            logger.info(f"tls client login request: {user}")
            login(request, user)
            response = HttpResponseRedirect(get_index_url())
            return set_auth_cookies(request, response)
        elif request.path_info == reverse("valid"):
            logger.debug(f"tls client valid request: {user}")
            request.user = user
        else:
            logger.warn(
                f"tls client ignoring unexpected request location: {request.path_info}"
            )
        return self.get_response(request)
