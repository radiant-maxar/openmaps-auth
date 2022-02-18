import logging
import requests
from bs4 import BeautifulSoup
from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver


logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def openmaps_login(sender, **kwargs):
    request = kwargs.get("request")
    user = kwargs.get("user")

    # Generate OSM session.
    cookie_resp = requests.get(settings.OSM_BASE_URL)
    cookies = cookie_resp.cookies
    osm_session = cookies[settings.OSM_SESSION_KEY]
    logger.debug(f"osm session for {user.email}: {osm_session}")

    # Get OSM CSRF token.
    login_url = f"{settings.OSM_BASE_URL}/login"
    login_resp = requests.get(login_url, cookies=cookies)
    authenticity_token = (
        BeautifulSoup(login_resp.content, features="html.parser")
        .find("meta", {"name": "csrf-token"})
        .get("content")
    )

    # Login to OSM.
    login_data = {
        "utf8": "✓",
        "referer": "",
        "authenticity_token": authenticity_token,
        "username": user.email,
        "commit": "Login",
        "password": settings.OSM_USER_PASSWORD,
    }
    login_resp = requests.post(
        login_url, allow_redirects=False, cookies=cookies, data=login_data
    )
    if login_resp.headers.get("location") != settings.OSM_BASE_URL:
        logger.error(f"Failed to login into OSM for user: {user.email}")
        raise Exception
    else:
        request.session[settings.OSM_SESSION_KEY] = osm_session
