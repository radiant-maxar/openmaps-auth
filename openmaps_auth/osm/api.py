import logging
import xml.dom.minidom

import requests
from django.conf import settings


logger = logging.getLogger(__name__)


def user_details(user):
    """
    Returns a dictionary of the results of a user details OpenStreetMap API call.
    """
    details_resp = requests.get(
        settings.OSM_USER_DETAILS_URL, auth=(user.email, user.osm_password)
    )
    try:
        dom = xml.dom.minidom.parseString(details_resp.content)
    except ValueError:
        logger.warn("could not parse user details xml")
        return None
    user = dom.getElementsByTagName("user")[0]
    return {
        "account_created": user.getAttribute("account_created"),
        "country": user.getAttribute("country"),
        "display_name": user.getAttribute("display_name"),
        "email": user.getAttribute("email"),
        "full_name": user.getAttribute("full_name"),
        "id": user.getAttribute("id"),
    }
