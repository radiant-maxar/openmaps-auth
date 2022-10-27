import logging
import requests
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import BadRequest, PermissionDenied
from django.dispatch import receiver

from .. import osm


logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def osm_login(sender, **kwargs):
    """
    Performs a login on an OpenStreetMap instance and adds its cookie to the
    sending request's sessions.
    """
    request = kwargs.get("request")
    user = kwargs.get("user")
    ol = osm.login(user)
    if ol.login_response.headers.get("location") != settings.OSM_BASE_URL:
        new_user_data = {
            "authenticity_token": ol.authenticity_token,
            "username": user.email,
        }
        response = requests.post(
            settings.OSM_NEW_USER_URL, cookies=ol.cookies, data=new_user_data
        )
        if response.status_code == 204:
            logger.info(f"created new osm user: {user}")
            ol = osm.login(user)
            if ol.login_response.headers.get("location") != settings.OSM_BASE_URL:
                logger.error(f"failed to login into osm after user creation: {user}")
                raise BadRequest
        else:
            logger.error(f"failed to login into osm for user: {user}")
            raise PermissionDenied
    request.session[settings.OSM_SESSION_KEY] = ol.osm_session
