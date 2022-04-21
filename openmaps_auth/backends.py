import os
import secrets
import time
from urllib.parse import urljoin, urlparse, urlunparse
from xml.dom import minidom

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from jose import jwt
from social_core.backends.okta_openidconnect import (
    OktaOpenIdConnect as BaseOktaOpenIdConnect,
)
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.backends.openstreetmap import (
    OpenStreetMapOAuth as BaseOpenStreetMapOAuth,
)


class LoginGovOpenIdConnect(OpenIdConnectAuth):
    name = "login-gov"

    ACR_VALUES = "http://idmanagement.gov/ns/assurance/ial/1"
    DEFAULT_SCOPE = ["openid", "email"]
    JWT_DECODE_OPTIONS = {"leeway": 30}
    TOKEN_TTL_SEC = 5 * 60  # 5 minutes into the future.

    @property
    def OIDC_ENDPOINT(self):
        return self.setting("OIDC_ENDPOINT", "https://secure.login.gov")

    def auth_allowed(self, response, details):
        """
        Only allow authentication from accounts with verified email addresses.
        """
        if details.get("email_verified"):
            return super().auth_allowed(response, details)
        else:
            return False

    def auth_complete_params(self, state=None):
        return {
            "client_assertion": self.generate_client_secret(),
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "code": self.data.get("code", ""),
            "grant_type": "authorization_code",
        }

    def auth_params(self, state=None):
        params = {"acr_values": self.ACR_VALUES}
        params.update(super().auth_params(state))
        return params

    def generate_client_secret(self):
        now = int(time.time())
        client_id = self.setting("KEY")
        private_key = self.setting("SECRET")
        payload = {
            "iss": client_id,
            "sub": client_id,
            "aud": self.access_token_url(),
            "jti": secrets.token_urlsafe(32),
            "exp": now + self.TOKEN_TTL_SEC,
        }
        return jwt.encode(payload, key=private_key, algorithm=self.JWT_ALGORITHMS[0])

    def get_jwks_keys(self):
        # Workaround until this fix released:
        # https://github.com/python-social-auth/social-core/pull/661
        keys = super().get_jwks_keys()
        for key in keys:
            key["alg"] = self.JWT_ALGORITHMS[0]
        return keys

    def get_key_and_secret(self):
        client_id = self.setting("KEY")
        client_secret = self.generate_client_secret()
        return client_id, client_secret

    def get_redirect_uri(self, state=None):
        return self.setting("REDIRECT_URI", super().get_redirect_uri(state))

    def get_user_details(self, response):
        user_details = super().get_user_details(response)
        user_details["email_verified"] = response["email_verified"]
        return user_details


class OktaOpenIdConnect(BaseOktaOpenIdConnect):
    def get_redirect_uri(self, state=None):
        return self.setting("REDIRECT_URI", super().get_redirect_uri(state))

    # This fix for Okta OIDC configuration URLs copied from:
    # https://github.com/python-social-auth/social-core/pull/663
    def oidc_config_url(self):
        # https://developer.okta.com/docs/reference/api/oidc/#well-known-openid-configuration
        url = urlparse(self.api_url())

        # If the URL path does not contain an authorizedServerId, we need
        # to truncate the path in order to generate a proper openid-configuration
        # URL.
        if url.path == "/oauth2/":
            url = url._replace(path="")

        return urljoin(
            urlunparse(url),
            "./.well-known/openid-configuration?client_id={}".format(
                self.setting("KEY")
            ),
        )

    def oidc_config(self):
        return self.get_json(self.oidc_config_url())


class OpenStreetMapOAuth(BaseOpenStreetMapOAuth):
    AUTHORIZATION_URL = f"{settings.OSM_AUTH_URL}/oauth/authorize"
    REQUEST_TOKEN_URL = f"{settings.OSM_AUTH_URL}/oauth/request_token"
    ACCESS_TOKEN_URL = f"{settings.OSM_AUTH_URL}/oauth/access_token"

    def get_redirect_uri(self, state=None):
        return self.setting("REDIRECT_URI", super().get_redirect_uri(state))

    def user_data(self, access_token, *args, **kwargs):
        """Return user data provided by OSM"""
        response = self.oauth_request(
            access_token, f"{settings.OSM_AUTH_URL}/api/0.6/user/details"
        )
        try:
            dom = minidom.parseString(response.content)
        except ValueError:
            return None
        user = dom.getElementsByTagName("user")[0]
        try:
            avatar = dom.getElementsByTagName("img")[0].getAttribute("href")
        except IndexError:
            avatar = None
        return {
            "id": user.getAttribute("id"),
            "username": user.getAttribute("display_name"),
            "account_created": user.getAttribute("account_created"),
            "avatar": avatar,
        }
