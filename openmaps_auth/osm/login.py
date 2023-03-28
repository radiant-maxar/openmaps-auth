import collections
import logging

import bs4
import requests
from django.conf import settings


logger = logging.getLogger(__name__)


OSMLogin = collections.namedtuple(
    "OSMLogin", ["authenticity_token", "cookies", "login_response", "osm_session"]
)


def login(user):
    """
    Performs a login against an OpenStreetMap instance, returning a 4-tuple of
    an authenticity token string, an initial request cookies object, the
    login response object, and an OSM session identifier string.
    """
    # Generate OSM session.
    response = requests.get(settings.OSM_BASE_URL)
    cookies = response.cookies
    osm_session = cookies[settings.OSM_SESSION_KEY]
    logger.debug(f"osm session for {user}: {osm_session}")

    # Get OSM CSRF token.
    response = requests.get(settings.OSM_LOGIN_URL, cookies=cookies)
    authenticity_token = (
        bs4.BeautifulSoup(response.content, features="html.parser")
        .find("meta", {"name": "csrf-token"})
        .get("content")
    )

    # Login to OSM.
    login_data = {
        "referer": "",
        "authenticity_token": authenticity_token,
        "username": user.email,
        "commit": "Login",
        "password": user.osm_password,
    }
    login_response = requests.post(
        settings.OSM_LOGIN_URL, allow_redirects=False, cookies=cookies, data=login_data
    )

    return OSMLogin(authenticity_token, cookies, login_response, osm_session)
