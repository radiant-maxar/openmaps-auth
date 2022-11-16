import io
import logging

from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import (
    FileResponse,
    Http404,
    HttpResponse,
    HttpResponseRedirect,
)
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone

from ..models import Certificate


logger = logging.getLogger(__name__)


def get_certificate(user, pk):
    try:
        return Certificate.objects.get(user=user, pk=pk)
    except Certificate.DoesNotExist:
        raise Http404


def get_user_certs(user):
    now = timezone.now()
    return (
        Certificate.objects.filter(user=user)
        .filter(start__lte=now)
        .filter(end__gte=now)
        .order_by("-end")
    )


@login_required
def cert_delete(request, pk):
    cert = get_certificate(request.user, pk)
    cert.delete()
    messages.add_message(request, messages.WARNING, f"Deleted certificate: {pk}")
    return HttpResponseRedirect(reverse("cert_list"))


@login_required
def cert_details(request, pk):
    return render(
        request,
        "cert_details.html",
        {
            "cert": get_certificate(request.user, pk),
        },
    )


@login_required
def cert_download(request, pk, modern=False):
    cert = get_certificate(request.user, pk)
    with open(cert.p12_file, "rb") as p12_fh:
        p12_data = p12_fh.read()
    if modern:
        p12_password = request.user.pkcs12_password.encode("utf-8")
        p12_obj = pkcs12.load_key_and_certificates(p12_data, p12_password)
        p12_data = pkcs12.serialize_key_and_certificates(
            b"",
            p12_obj[0],
            p12_obj[1],
            None,
            BestAvailableEncryption(p12_password),
        )
        logger.info(f"{request.user.email} downloaded modern certificate {cert.pk}")
    else:
        logger.info(f"{request.user.email} downloaded certificate {cert.pk}")
    return FileResponse(
        io.BytesIO(p12_data),
        as_attachment=True,
        content_type="application/octet-stream",
        filename=cert.p12_name,
    )


@login_required
def cert_modern(request, pk):
    return cert_download(request, pk, modern=True)


@login_required
def cert_list(request):
    return render(
        request,
        "cert_list.html",
        {
            "certificates": get_user_certs(request.user),
        },
    )


@login_required
def cert_new(request):
    if (
        get_user_certs(request.user).count()
        >= settings.OPENMAPS_AUTH_CLIENT_TLS_MAX_CERTS
    ):
        messages.add_message(
            request,
            messages.ERROR,
            f"Cannot have more than {settings.OPENMAPS_AUTH_CLIENT_TLS_MAX_CERTS} valid certificates",
        )
        return HttpResponseRedirect(reverse("cert_list"))
    cert = Certificate(user=request.user)
    cert.save()
    messages.add_message(
        request, messages.SUCCESS, f"Successfully created certificate: {cert.pk}"
    )
    return HttpResponseRedirect(reverse("cert_details", args=[cert.pk]))


@login_required
def pkcs12_password(request):
    return HttpResponse(
        request.user.pkcs12_password,
        content_type="text/plain",
    )
