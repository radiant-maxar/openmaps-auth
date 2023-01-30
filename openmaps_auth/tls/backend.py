import logging
import urllib.parse

from cryptography import x509
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from ..models import Certificate


logger = logging.getLogger(__name__)


def cert_from_tls_request(request):
    cert = None
    verify = request.headers.get(settings.OPENMAPS_AUTH_CLIENT_TLS_VERIFY_HEADER)
    if verify == "SUCCESS":
        cert_urlencoded = request.headers.get(
            settings.OPENMAPS_AUTH_CLIENT_TLS_CERT_HEADER
        )
        # Nginx prefers to URL-encoded client certificates, decode using
        # a fake query string.
        cert_pem = urllib.parse.parse_qs(f"cert={cert_urlencoded}")["cert"][0].encode(
            "ascii"
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
    elif verify and verify.startswith("FAIL"):
        logger.warn(f"tls client failure: {verify}")
    return cert


def email_from_tls_cert(cert):
    email = None
    if cert:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        if san_ext:
            cert_emails = san_ext.value.get_values_for_type(x509.RFC822Name)
            if cert_emails:
                if len(cert_emails) > 1:
                    logger.warn(
                        "multiple email subject alternative names encountered, only first is used"
                    )
                email = cert_emails[0]
        else:
            logger.warn("no subject alternative name extension found in certificate")
    return email


def tls_cert_allowed(cert):
    if not cert:
        return False
    allowed = True
    if settings.OPENMAPS_AUTH_CLIENT_TLS_VERIFY_SERIAL:
        allowed = Certificate.objects.filter(serial=cert.serial_number).exists()
        if not allowed:
            logger.warn(f"tls client denied: {cert.serial_number}")
    return allowed


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
        cert = cert_from_tls_request(request)
        if not tls_cert_allowed(cert):
            return None
        email = email_from_tls_cert(cert)
        if not tls_email_allowed(email):
            return None
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(**{UserModel.USERNAME_FIELD: email})
        except UserModel.DoesNotExist:
            logger.info(f"creating user for {email}")
            user = UserModel(**{UserModel.USERNAME_FIELD: email})
            user.save()
        logger.debug(f"tls client authenticated: {email}")
        return user
