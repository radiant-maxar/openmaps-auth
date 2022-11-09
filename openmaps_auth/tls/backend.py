import logging
import urllib.parse

from cryptography import x509
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


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
        client_cert = x509.load_pem_x509_certificate(client_cert_pem)
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
            user = UserModel(**{UserModel.USERNAME_FIELD: email})
            user.save()

        logger.info(f"tls client authenticated: {email}")
        return user
