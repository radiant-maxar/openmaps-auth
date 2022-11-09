import datetime
import logging
import os
import os.path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256
from django.conf import settings
from django.core.exceptions import BadRequest
from django.db.models.signals import pre_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone

from ..models import Certificate


logger = logging.getLogger(__name__)


@receiver(pre_save, sender=Certificate)
def cert_create(sender, **kwargs):
    """
    Before saving a `Certificate` model, ensure that it is created
    and signed by the Smallstep CA and put in place on the filesystem.
    """
    cert = kwargs.get("instance")
    if cert.serial:
        # If serial number already exists, then don't try and issue again
        # in the `save()` call and return.
        logger.debug(f"certificate already exists")
        return

    # Ensure output directories exist.
    if not os.path.isdir(settings.STEP_CERTS):
        os.mkdir(settings.STEP_CERTS, mode=0o0755)
        logger.info(f"created step certficate directory: {settings.STEP_CERTS}")
    if not os.path.isdir(cert.certs_path):
        os.mkdir(cert.certs_path, mode=0o0750)
        logger.info(f"created user certficate directory: {cert.certs_path}")
    if not os.path.isdir(settings.STEP_SECRETS):
        os.mkdir(settings.STEP_SECRETS, mode=0o0750)
        logger.info(f"created step secrets directory: {settings.STEP_SECRETS}")
    if not os.path.isdir(cert.secrets_path):
        os.mkdir(cert.secrets_path, mode=0o0750)
        logger.info(f"created user secrets directory: {cert.secrets_path}")

    # Generate and sign certificate; any transitory key material and password
    # files within a temporary directory that's deleted after use.
    with tempfile.TemporaryDirectory() as temp_dir:
        step_ca_cert_args = [
            settings.STEP_CLI,
            "ca",
            "certificate",
            cert.user.email,
            cert.cert_file,
            cert.key_file,
            "--provisioner",
            settings.STEP_PROVISIONER,
            "--provisioner-password-file",
            settings.STEP_PROVISIONER_PASSWORD_FILE,
            "--not-after",
            f"{settings.OPENMAPS_AUTH_CLIENT_TLS_DURATION}h",
        ]
        logger.debug(f"step ca certificate args: {step_ca_cert_args}")
        status, output = subprocess.getstatusoutput(" ".join(step_ca_cert_args))
        if status != 0:
            logger.error(f"failed to create certificate: {output}")
            raise BadRequest

        # Create temporary p12 password file.
        p12_password_file = os.path.join(temp_dir, "p12-password.txt")
        with open(p12_password_file, "wt") as p12_fh:
            p12_fh.write(cert.user.pkcs12_password)

        # We're using Smallstep CLI to generate the P12 instead of Python's
        # cryptography as it's impossible to create P12 files compatible with
        # OpenJDK 8 on systems with OpenSSL 3.0+.
        step_cert_p12_args = [
            settings.STEP_CLI,
            "certificate",
            "p12",
            "--force",
            "--password-file",
            p12_password_file,
            cert.p12_file,
            cert.cert_file,
            cert.key_file,
        ]
        logger.debug(f"step certificate p12 args: {step_cert_p12_args}")
        status, output = subprocess.getstatusoutput(" ".join(step_cert_p12_args))
        if status != 0:
            logger.error(f"failed to create p12 file: {output}")
            raise BadRequest

    # Inspect the certificate to get the validity dates, serial number, and fingerprint.
    with open(cert.cert_file, "rb") as cert_fh:
        tls_cert = x509.load_pem_x509_certificate(cert_fh.read())
    cert.fingerprint = "".join("%02x" % b for b in tls_cert.fingerprint(SHA256()))
    # Use string instead of trying to represent 2**159 integer.
    cert.serial = str(tls_cert.serial_number)
    cert.start = timezone.make_aware(tls_cert.not_valid_before, timezone.utc)
    cert.end = timezone.make_aware(tls_cert.not_valid_after, timezone.utc)


@receiver(pre_delete, sender=Certificate)
def cert_revoke(sender, **kwargs):
    """
    Before deleting a `Certificate`, ensure that it is revoked by the
    Smallstep CA and the certificate files are removed.
    """
    cert = kwargs.get("instance")
    if cert.valid:
        revoke_reason_code = 9
        step_ca_revoke_args = [
            settings.STEP_CLI,
            "ca",
            "revoke",
            "--cert",
            cert.cert_file,
            "--key",
            cert.key_file,
            "--reasonCode",
            f"{revoke_reason_code}",
        ]
        logger.debug(f"step ca revoke args: {step_ca_revoke_args}")
        status, output = subprocess.getstatusoutput(" ".join(step_ca_revoke_args))
        if status != 0:
            logger.error(f"failed to revoke certificate: {output}")
            raise BadRequest
        logger.info(f"step ca revoked certificate with serial {cert.serial}")
    else:
        logger.info(
            f"skipping step ca revocation for certificate with serial {cert.serial}"
        )

    if os.path.isfile(cert.key_file):
        os.remove(cert.key_file)
        logger.info(f"deleted certificate key: {cert.key_file}")
    if os.path.isfile(cert.p12_file):
        os.remove(cert.p12_file)
        logger.info(f"deleted certificate p12: {cert.p12_file}")
    if os.path.isfile(cert.cert_file):
        os.remove(cert.cert_file)
        logger.info(f"deleted certificate cert: {cert.cert_file}")
