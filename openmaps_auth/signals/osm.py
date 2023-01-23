import logging
import re
import requests
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import BadRequest, PermissionDenied
from django.dispatch import receiver

from .. import osm


logger = logging.getLogger(__name__)
valid_accept_language = re.compile(r"^[a-zA-z ,\*\-]+$").match


@receiver(user_logged_in)
def osm_login(sender, **kwargs):
    """
    Performs a login on an OpenStreetMap instance and adds its cookie to the
    sending request's sessions.
    """
    request = kwargs.get("request")
    user = kwargs.get("user")
    ol = osm.login(user)
    if ol.login_response.headers.get("location").rstrip("/") != settings.OSM_BASE_URL:
        # New user's roles: make administrator when a superuser.
        user_roles = ["moderator"]
        if (
            user.is_superuser
            or user.email in settings.OSM_USER_ADMINS
            or settings.OSM_USER_ALL_ADMINS
        ):
            user_roles.append("administrator")
        user_roles_str = ",".join(user_roles)
        logger.debug(f"osm user roles: {user_roles_str}")

        new_user_data = {
            "authenticity_token": ol.authenticity_token,
            "email": user.email,
            "password": user.osm_password,
            "roles": user_roles_str,
        }

        # Set full_name/display_name if user has first/last name.
        if user.first_name and user.last_name:
            full_name = user.get_full_name()
            logger.debug(f"osm user full name: {full_name}")
            new_user_data.update(
                {
                    "display_name": full_name,
                    "full_name": full_name,
                }
            )

        # Set organization/country/location/languages when defined in settings.
        if settings.OSM_USER_ORGANIZATION:
            new_user_data.update({"organization": settings.OSM_USER_ORGANIZATION})
            logger.debug(
                f"osm user organization from setting: {settings.OSM_USER_ORGANIZATION}"
            )

        if settings.OSM_USER_COUNTRY:
            new_user_data.update({"country": settings.OSM_USER_COUNTRY})
            logger.debug(f"osm user country from setting: {settings.OSM_USER_COUNTRY}")

        if settings.OSM_USER_HOME_LAT and settings.OSM_USER_HOME_LON:
            logger.debug(
                "osm user home lat,lon,zoom from settings: "
                f"{settings.OSM_USER_HOME_LAT},{settings.OSM_USER_HOME_LON},{settings.OSM_USER_HOME_ZOOM}"
            )
            new_user_data.update(
                {
                    "home_lat": settings.OSM_USER_HOME_LAT,
                    "home_lon": settings.OSM_USER_HOME_LON,
                    "home_zoom": settings.OSM_USER_HOME_ZOOM,
                }
            )

        if settings.OSM_USER_LANGUAGES:
            new_user_data.update({"languages": settings.OSM_USER_LANGUAGES})
            logger.debug(
                f"osm user languages from setting: {settings.OSM_USER_LANGUAGES}"
            )
        else:
            # Attempt to set languages/country from Accept-Language header.
            accept_language = request.META.get("HTTP_ACCEPT_LANGUAGE")
            if accept_language:
                accept_language = accept_language.split(";")[0].strip()
                if valid_accept_language(accept_language):
                    new_user_data.update({"languages": accept_language})
                    logger.debug(f"osm user languages from header: {accept_language}")
                    if not settings.OSM_USER_COUNTRY:
                        primary_lang = accept_language.split(",")[0].split("-")
                        if len(primary_lang) == 2:
                            country = primary_lang[1].upper()
                            logger.debug(f"osm user country from header: {country}")
                            new_user_data.update({"country": country})
            else:
                logger.warn("invalid accept-language header detected")

        response = requests.post(
            settings.OSM_NEW_USER_URL, cookies=ol.cookies, data=new_user_data
        )
        if response.status_code == 204:
            logger.info(f"created new osm user: {user}")
            ol = osm.login(user)
            if ol.login_response.headers.get("location").rstrip("/") != settings.OSM_BASE_URL:
                logger.error(f"failed to login into osm after user creation: {user}")
                raise BadRequest
        else:
            logger.error(f"failed to login into osm for user: {user}")
            raise PermissionDenied
    request.session[settings.OSM_SESSION_KEY] = ol.osm_session
