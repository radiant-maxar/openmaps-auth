import io
import logging
import xml.dom.minidom
import xml.etree.ElementTree

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse

from .. import osm


logger = logging.getLogger(__name__)


def josm_preferences_xml(user):
    josm_preferences = xml.etree.ElementTree.Element("preferences")
    josm_preferences.attrib["version"] = settings.JOSM_PREFERENCES_VERSION
    josm_preferences.attrib["xmlns"] = settings.JOSM_PREFERENCES_XMLNS
    preference_tags = tuple(
        (item.get("key"), item.get("value")) for item in settings.JOSM_PREFERENCES
    )
    preference_tags += (
        ("oauth.access-token.key", user.josm_oauth1_token_key),
        ("oauth.access-token.secret", user.josm_oauth1_token_secret),
        ("oauth.settings.consumer-key", user.josm_oauth1_key),
        ("oauth.settings.consumer-secret", user.josm_oauth1_secret),
        ("oauth.settings.use-default", "false"),
        ("osm-server.auth-method", "oauth"),
        ("user-cert.pass", user.pkcs12_password),
        ("user-cert.path", "{}.p12".format(user.email.split("@")[0])),
    )
    for tag_key, tag_value in preference_tags:
        tag = xml.etree.ElementTree.SubElement(josm_preferences, "tag")
        tag.attrib["key"] = tag_key
        tag.attrib["value"] = tag_value
    return xml.dom.minidom.parseString(
        xml.etree.ElementTree.tostring(
            josm_preferences,
            encoding="unicode",
        )
    ).toprettyxml(indent="  ")


@login_required
def preferences(request):
    refresh = request.GET.get("refresh") == "1"
    if (
        refresh
        or not request.user.josm_oauth1_key
        or not request.user.josm_oauth1_secret
    ):
        logger.info(f"refreshing josm oauth1 details for {request.user}")
        josm_oauth1 = osm.oauth1_application(
            request.user,
            settings.JOSM_OAUTH1_NAME,
            allow_read_gpx=True,
            allow_read_prefs=True,
            allow_write_api=True,
            allow_write_diary=True,
            allow_write_gpx=True,
            allow_write_notes=True,
            allow_write_prefs=True,
            callback_uri=settings.JOSM_OAUTH1_CALLBACK_URI,
        )
        request.user.josm_oauth1_key = josm_oauth1["key"]
        request.user.josm_oauth1_secret = josm_oauth1["secret"]
        request.user.josm_oauth1_token_key = josm_oauth1["token_key"]
        request.user.josm_oauth1_token_secret = josm_oauth1["token_secret"]
        request.user.save()

    content_type = "application/xml"
    preferences_xml = josm_preferences_xml(request.user)
    if request.GET.get("inline") == "1":
        return HttpResponse(
            preferences_xml,
            content_type=content_type,
        )
    else:
        return FileResponse(
            io.BytesIO(preferences_xml.encode("utf-8")),
            as_attachment=True,
            content_type=content_type,
            filename="preferences.xml",
        )
