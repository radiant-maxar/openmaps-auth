import logging
import os.path
import urllib.parse

import bs4
import requests
from django.conf import settings
from requests_oauthlib import OAuth1Session

from . import api
from .login import login


logger = logging.getLogger(__name__)


def get_authenticity_token(content):
    return (
        bs4.BeautifulSoup(content, "html.parser")
        .find("input", {"name": "authenticity_token"})
        .get("value")
    )


def oauth1_application(
    user,
    name,
    allow_read_gpx=False,
    allow_read_prefs=True,
    allow_write_api=False,
    allow_write_diary=False,
    allow_write_gpx=False,
    allow_write_notes=False,
    allow_write_prefs=False,
    callback_uri="",
    callback_url="",
    support_url="",
):
    """
    Gets or creates an OAuth1 application on the OpenStreetMap instance for the given
    user and application name; returns a dict including the application's details,
    including its key and secret.
    """
    ol = login(user)

    # oauth1 client applications
    user_details = api.user_details(user)
    display_name = user_details["display_name"]
    clients_url = f"{settings.OSM_BASE_URL}/user/{display_name}/oauth_clients"
    logger.debug(f"clients_url: {clients_url}")
    clients_resp = requests.get(clients_url, cookies=ol.cookies)
    clients_soup = bs4.BeautifulSoup(clients_resp.content, "html.parser")
    clients_divs = clients_soup.find_all("div", {"class": ["client_application"]})

    oauth1_url = None
    for client_div in clients_divs:
        app_link = client_div.find("a")
        # XXX: Only the first application matching the name is used.
        if app_link.text == name:
            oauth1_location = app_link["href"]
            oauth1_url = urllib.parse.urljoin(settings.OSM_BASE_URL, oauth1_location)
    if not oauth1_url:
        # create new oauth1 client application
        new_client_url = f"{clients_url}/new"
        new_client_init = requests.get(
            new_client_url, allow_redirects=False, cookies=ol.cookies
        )
        new_client_data = {
            "authenticity_token": get_authenticity_token(new_client_init.content),
            "client_application[name]": name,
            "client_application[url]": settings.OSM_BASE_URL,
            "client_application[support_url]": support_url,
            "client_application[callback_url]": callback_url,
            "client_application[allow_read_prefs]": "1" if allow_read_prefs else "0",
            "client_application[allow_write_prefs]": "1" if allow_write_prefs else "0",
            "client_application[allow_write_diary]": "1" if allow_write_diary else "0",
            "client_application[allow_write_api]": "1" if allow_write_api else "0",
            "client_application[allow_read_gpx]": "1" if allow_read_gpx else "0",
            "client_application[allow_write_gpx]": "1" if allow_write_gpx else "0",
            "client_application[allow_write_notes]": "1" if allow_write_notes else "0",
            "commit": "Register",
        }
        logger.debug(f"new oauth1_application data: {new_client_data}")
        app_resp = requests.post(clients_url, new_client_data, cookies=ol.cookies)
        oauth1_location = app_resp.request.path_url
        logger.info(
            f"created new oauth1_application for {user.email}: {oauth1_location}"
        )
    else:
        logger.debug(f"existing oauth1_application: {oauth1_location}")
        app_resp = requests.get(oauth1_url, cookies=ol.cookies)

    # Parse out OAuth1 key/secret out of HTML; this page has parsing issues due to a
    # missing `</dd>` element, so it must be done "manually".
    app_soup = bs4.BeautifulSoup(app_resp.content, "html.parser")
    app_dds = app_soup.find_all("dd")
    oauth1_key = app_dds[0].text.split()[0]
    oauth1_secret = app_dds[1].text

    # Authorize an OAuth1 access token key and secret for the application.
    with OAuth1Session(
        oauth1_key,
        client_secret=oauth1_secret,
        callback_uri=callback_uri,
    ) as oauth1_session:
        oauth1_session.cookies.update(ol.cookies)
        req_token = oauth1_session.fetch_request_token(
            settings.OSM_OAUTH1_REQUEST_TOKEN_URL
        )
        auth_url = oauth1_session.authorization_url(
            settings.OSM_OAUTH1_AUTHORIZATION_URL
        )
        auth_init = oauth1_session.get(auth_url, allow_redirects=False)
        authorize_data = {
            "authenticity_token": get_authenticity_token(auth_init.content),
            "oauth_token": req_token["oauth_token"],
            "allow_read_prefs": "1" if allow_read_prefs else "0",
            "allow_write_prefs": "1" if allow_write_prefs else "0",
            "allow_write_diary": "1" if allow_write_diary else "0",
            "allow_write_api": "1" if allow_write_api else "0",
            "allow_read_gpx": "1" if allow_read_gpx else "0",
            "allow_write_gpx": "1" if allow_write_gpx else "0",
            "allow_write_notes": "1" if allow_write_notes else "0",
            "commit": "Grant Access",
        }
        auth_resp = oauth1_session.post(
            settings.OSM_OAUTH1_AUTHORIZATION_URL, authorize_data, allow_redirects=False
        )
        oauth1_session.parse_authorization_response(auth_resp.headers["location"])
        access_token = oauth1_session.fetch_access_token(
            settings.OSM_OAUTH1_ACCESS_TOKEN_URL
        )
        oauth1_token_key = access_token["oauth_token"]
        oauth1_token_secret = access_token["oauth_token_secret"]

    return {
        "key": oauth1_key,
        "secret": oauth1_secret,
        "name": name,
        "location": oauth1_location,
        "id": int(os.path.basename(oauth1_location)),
        "token_key": oauth1_token_key,
        "token_secret": oauth1_token_secret,
    }
