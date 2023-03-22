import io
import logging
import xml.dom.minidom
import xml.etree.ElementTree

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponse

from ..osm.oauth import oauth1_application


logger = logging.getLogger(__name__)


def josm_preferences_xml(user):
    josm_preferences = xml.etree.ElementTree.Element("preferences")
    josm_preferences.attrib["version"] = settings.JOSM_PREFERENCES_VERSION
    josm_preferences.attrib["xmlns"] = settings.JOSM_PREFERENCES_XMLNS

    # Add any tag elements.
    preference_tags = settings.JOSM_PREFERENCES.get("tags", {})
    preference_tags.update(
        {
            "oauth.access-token.key": user.josm_oauth1_token_key,
            "oauth.access-token.secret": user.josm_oauth1_token_secret,
            "oauth.settings.consumer-key": user.josm_oauth1_key,
            "oauth.settings.consumer-secret": user.josm_oauth1_secret,
            "oauth.settings.use-default": "false",
            "osm-server.auth-method": "oauth",
            "user-cert.pass": user.pkcs12_password,
            "user-cert.path": "{}.p12".format(user.email_local_part),
        }
    )
    for tag_key, tag_value in preference_tags.items():
        tag_elem = xml.etree.ElementTree.SubElement(josm_preferences, "tag")
        tag_elem.attrib["key"] = tag_key
        tag_elem.attrib["value"] = tag_value

    # Add any list elements.
    for list_key, list_value in settings.JOSM_PREFERENCES.get("lists", {}).items():
        list_elem = xml.etree.ElementTree.SubElement(josm_preferences, "list")
        list_elem.attrib["key"] = list_key
        for entry in list_value:
            entry_tag = xml.etree.ElementTree.SubElement(list_elem, "entry")
            entry_tag.attrib["value"] = entry

    # Add any maps elements.
    for maps_key, maps_value in settings.JOSM_PREFERENCES.get("maps", {}).items():
        maps_elem = xml.etree.ElementTree.SubElement(josm_preferences, "maps")
        maps_elem.attrib["key"] = maps_key
        for map_dict in maps_value:
            map_elem = xml.etree.ElementTree.SubElement(maps_elem, "map")
            for tag_key, tag_value in map_dict.items():
                map_tag = xml.etree.ElementTree.SubElement(map_elem, "tag")
                map_tag.attrib["key"] = tag_key
                map_tag.attrib["value"] = tag_value

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
        josm_oauth1 = oauth1_application(
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
