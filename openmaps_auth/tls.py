import logging
import urllib.parse

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.urls import reverse

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    raise ImproperlyConfigured("cryptography package is required")

from .cookies import set_auth_cookies
from .views import get_index_url


logger = logging.getLogger(__name__)


def email_from_tls_request(request):
    email = None
    verify = request.headers.get(settings.OPENMAPS_AUTH_CLIENT_TLS_VERIFY_HEADER)
    if verify == "SUCCESS":
        client_cert_urlencoded = request.headers.get(
            settings.OPENMAPS_AUTH_CLIENT_TLS_CERT_HEADER
        )
        # Nginx prefers to URL-encoded client certificate, decode using
        # a fake query string.
        client_cert_pem = urllib.parse.parse_qs(f"cert={client_cert_urlencoded}")[
            "cert"
        ][0].encode("ascii")
        client_cert = x509.load_pem_x509_certificate(client_cert_pem, default_backend())
        client_san_ext = client_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        if client_san_ext:
            client_emails = client_san_ext.value.get_values_for_type(x509.RFC822Name)
            if len(client_emails) > 1:
                logger.warn("multiple email signatures encountered, only first is used")
            elif client_emails:
                email = client_emails[0]
    elif verify and verify.startswith("FAIL"):
        logger.warn(f"tls client failure: {verify}")
    return email


def tls_email_allowed(email):
    if not email:
        return False
    emails = [email.lower() for email in settings.OPENMAPS_AUTH_WHITELISTED_EMAILS]
    domains = [domain.lower() for domain in settings.OPENMAPS_AUTH_WHITELISTED_DOMAINS]
    allowed = True
    if emails or domains:
        email = email.lower()
        domain = email.split("@", 1)[1]
        allowed = email in emails or domain in domains
        if not allowed:
            logger.warn(f"tls client denied: {email}")
    return allowed


class TLSClientBackend(ModelBackend):
    def authenticate(self, request, **kwargs):
        email = email_from_tls_request(request)
        if not tls_email_allowed(email):
            return None
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(**{UserModel.USERNAME_FIELD: email})
        except UserModel.DoesNotExist:
            logger.info(f"creating user for {email}")
            user = UserModel(
                **{UserModel.USERNAME_FIELD: email, UserModel.EMAIL_FIELD: email}
            )
            user.save()

        logger.info(f"tls client authenticated: {email}")
        return user


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
            logger.info(f"tls client valid request: {user}")
            request.user = user
        else:
            logger.warn(
                f"tls client ignoring unexpected request location: {request.path_info}"
            )
        return self.get_response(request)
