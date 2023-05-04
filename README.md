# OpenMaps Authentication API

This application enables authentication integrations for Maxar's OpenMaps environments. Specifically, this provides a simple API for mediating access to private web applications via external identity providers.

## Requirements

* Python 3.7+
* OAuth or OIDC credentials when using an identity provider.

## Usage

This application is typically used with Nginx's [`auth_request`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html) directive.  For example:

```
location = /index {
    proxy_pass http://auth:8000;
}

location = /callback {
    proxy_pass http://auth:8000;
}

location = /valid {
    internal;
    proxy_pass              http://auth:8000;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
}

location / {
    proxy_pass   http://protected-app;
    auth_request /valid;
}
```

## Configuration Reference

All listed setting may be set via an environment variable of the same name, or by using a file with the setting's contents and appending [`_FILE` to the setting name](https://django-environ.readthedocs.io/en/latest/tips.html#docker-style-file-based-variables).  Any file defaults with `/path/to/openmaps-auth` is the location where you've cloned this repository.

### Application Settings

#### `OPENMAPS_AUTH_APP_LINKS`

A JSON list of applications used when generating links on the index; defaults to:

```
[{"link": "/", "text": "MapEdit"}]
```

#### `OPENMAPS_AUTH_BASE_PATH`

Base path for all URLs, default is the empty string (`""`).

#### `OPENMAPS_AUTH_BACKEND`

Authentication backend to use, defaults to `None`.  Set this to the desired external identity provider:

* `login-gov`
* `okta-openidconnect`
* `openstreetmap`
* `openstreetmap-oauth2`

The following must also be configured when setting a backend:

* `OPENMAPS_AUTH_KEY`
* `OPENMAPS_AUTH_SECRET`
* `OPENMAPS_AUTH_OIDC_ENDPOINT`: when using Okta or for a Login.gov development endpoint.

#### `OPENMAPS_AUTH_CALLBACK_URL`

The callback URL used to set [`LOGIN_REDIRECT_URL`](https://docs.djangoproject.com/en/4.1/ref/settings/#std-setting-LOGIN_REDIRECT_URL); defaults to `callback`.

#### `OPENMAPS_AUTH_CLIENT_TLS`

When set, enables authentication with TLS client certificates; defaults to `False` unless both the `STEP_PROVISIONER` and `STEP_PROVISIONER_PASSWORD_FILE` are configured.  Requires having a [Smallstep certificate authority](https://smallstep.com/docs/step-ca) running and configured for use (e.g., `step ca bootstrap --ca-url https://my-step-ca`).  In addition, the [Smallstep CLI](https://smallstep.com/cli/), the `step` command, is required to be installed on the host.  Smallstep tool configuration and general TLS concepts are beyond the scope of this document.

Here's an example of additional [Nginx configuration](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) to enable authentication with TLS certificates:

```
ssl_client_certificate /path/to/ca-for-clients.pem;
ssl_verify_client optional;

...

location = /valid {
    internal;
    proxy_pass              http://auth:8000;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
    proxy_set_header        X-TLS-Client-Cert $ssl_client_escaped_cert;
    proxy_set_header        X-TLS-Client-Verify $ssl_client_verify;
}

location = /login {
    proxy_pass       http://auth:8000;
    proxy_set_header X-TLS-Client-Cert $ssl_client_escaped_cert;
    proxy_set_header X-TLS-Client-Verify $ssl_client_verify;
}
```

#### `OPENMAPS_AUTH_CLIENT_TLS_CERT_HEADER`

HTTP header for client certifcate in PEM format, and URL encoded like Nginx's [`$ssl_client_escaped_cert`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert) variable; defaults to `X-TLS-Client-Cert`.

#### `OPENMAPS_AUTH_CLIENT_TLS_VERIFY_HEADER`

HTTP header for client certifcate verification status like Nginx's [`$ssl_client_verify`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_verify) variable; defaults to `X-TLS-Client-Verify`.

#### `OPENMAPS_AUTH_CLIENT_TLS_DURATION`

The duration of issued client certificates, defaults to `744h`.

#### `OPENMAPS_AUTH_CLIENT_TLS_MAX_CERTS`

The maximum number of valid client certificates allowed to be issued to user, defaults to `3`.

#### `OPENMAPS_AUTH_CLIENT_TLS_VERIFY_SERIAL`

Defaults to `True`; when set, verify that the certificate's serial number is recorded in the database.  This allows the application to infer a certificate's validity without CRLs or OCSP queries.  Set to `False` to allow certificates not created with this application.

#### `OPENMAPS_AUTH_INDEX_URL`

The index URL to used to set [`LOGOUT_REDIRECT_URL`](https://docs.djangoproject.com/en/4.1/ref/settings/#logout-redirect-url) and `SOCIAL_AUTH_LOGIN_REDIRECT_URL`; defaults to `index`.

#### `OPENMAPS_AUTH_KEY`

The OAuth consumer key or OIDC client identifier when using a social authentication backend.

#### `OPENMAPS_AUTH_LOG_LEVEL`

The logging level for this application, defaults to `INFO`.

#### `OPENMAPS_AUTH_OIDC_ENDPOINT`

Set this to change OIDC endpoint URL from the default.

#### `OPENMAPS_AUTH_SECRET`

The OAuth consumer secret or OIDC private RSA key in PEM format.

#### `OPENMAPS_AUTH_TITLE`

The title to use in the generated pages, defaults to `Maxar OpenMaps`.

#### `OPENMAPS_AUTH_WHITELISTED_DOMAINS`

When using social or TLS authentication, domains [allowed to login](https://python-social-auth.readthedocs.io/en/latest/configuration/settings.html#whitelists).

#### `OPENMAPS_AUTH_WHITELISTED_EMAILS`

When using social or TLS authentication, email addresses [allowed to login](https://python-social-auth.readthedocs.io/en/latest/configuration/settings.html#whitelists).

#### `OPENMAPS_AUTH_OSM_SESSION`

Defaults to `False`; when set, a cookie from the configured OpenStreetMap instance will be added to the user's session.

#### `JOSM_PREFERENCES`

A JSON dictionary of additional lists, maps, or tag elements to add to the generated preferences file.  Defaults to:

```json
{
  "tags": {
    "default.osm.tile.source.url": "https://tile.openstreetmap.org/{zoom}/{x}/{y}.png",
  }
}
```

#### `JOSM_OAUTH1_CALLBACK_URI`

Defaults to `http://localhost:8111/callback`.

#### `JOSM_OAUTH1_NAME`

The name of the OAuth1 application to create for OSM users; defaults to `JOSM - Java OpenStreetMap Editor`.

#### `JOSM_PREFERENCES_VERSION`

The version of JOSM for the generated preferences file, defaults to `18303`.

#### `JOSM_PREFERENCES_XMLNS`

The XML namespace for the root `<preferences>` element in the generated JOSM preferences file, defaults to `http://josm.openstreetmap.de/preferences-1.0`.

#### `OSM_AUTH_URL`

Base URL for accessing OpenStreetMap authentication endpoints, defaults to the value of `OSM_BASE_URL`.

#### `OSM_BASE_URL`

Base URL to access OpenStreetMap at, defaults to `https://www.openstreetmap.org`.

#### `OSM_LOGIN_URL`

URL used to login to OpenStreetMap, defaults to `{OSM_BASE_URL}/login`.

#### `OSM_NEW_USER_URL`

URL used to create new OpenStreetMap users, defaults to `{OSM_BASE_URL}/user/new`.

#### `OSM_OAUTH1_ACCESS_TOKEN_URL`

URL used for OAuth1 access tokens; defaults to `{OSM_AUTH_URL}/oauth/access_token`.

#### `OSM_OAUTH1_AUTHORIZATION_URL`

URL used for OAuth1 authorization; defaults to `{OSM_AUTH_URL}/oauth/authorize`.

#### `OSM_OAUTH1_REQUEST_TOKEN_URL`

URL used for OAuth1 request tokens; defaults to `{OSM_AUTH_URL}/oauth/request_token`

#### `OSM_OAUTH2_ACCESS_TOKEN_URL`

URL used for OAuth2 access tokens; defaults to `{OSM_AUTH_URL}/oauth2/token`.

#### `OSM_OAUTH2_AUTHORIZATION_URL`

URL used for OAuth2 authorization; defaults to `{OSM_AUTH_URL}/oauth2/authorize`.

#### `OSM_OAUTH2_DEFAULT_SCOPE`

#### `OSM_SESSION_KEY`

Cookie used by OpenStreetMap to store its session, defaults to [`_osm_session`](https://github.com/openstreetmap/openstreetmap-website/blob/master/config/initializers/session_store.rb#L4).

#### `OSM_USER_ADMINS`

A JSON list of OSM user email addresses that will be granted the `administrator` role when created, defaults to `[]`.

#### `OSM_USER_ALL_ADMINS`

When enabled, all OSM users will be granted the `administrator` role when created, defaults to `False`.

#### `OSM_USER_COUNTRY`

The country to use for all OSM users created instead of inferring from browser request headers, defaults to `None`.

#### `OSM_USER_DETAILS_URL`

URL used to query OpenStreetMap user details, defaults to `{OSM_AUTH_URL}/api/0.6/user/details`.

#### `OSM_USER_EMAIL_DOMAIN`

When using OpenStreetMap as an authentication backend, the domain to use for user email addresses since they're not provided by OSM; defaults to `openstreetmap.arpa`.

#### `OSM_USER_HOME_LAT`

The default home latitude to use for created OSM users, defaults to `None`.

#### `OSM_USER_HOME_LON`

The default home longitude to use for created OSM users, defaults to `None`.

#### `OSM_USER_HOME_ZOOM`

The default zoom level to use for created OSM users, defaults to `14`.

#### `OSM_USER_LANGUAGES`

The languages to use for all created OSM users instead of inferring from request headers, defaults to `None`.

#### `OSM_USER_NAME_REPLACE_SPACE`

Replace any spaces in the OSM user name with this value.

#### `OSM_USER_NAME_LOWER`

Make the OSM user name lower case.

#### `OSM_USER_ORGANIZATION`

The organization to use for all created OSM users, defaults to `None`.

#### `STEPPATH`

The path used by Smallstep CA tools, defaults to `/path/to/openmaps-auth/.step`.

#### `STEP_CERTS`

The path used for Smallstep CA certificate files, defaults to `${STEPPATH}/certs`.

#### `STEP_CLI`

Path to the [Smallstep CLI](https://smallstep.com/cli/) binary, defaults to `step`.

#### `STEP_PROVISIONER`

The name of the [Smallstep CA](https://smallstep.com/certificates/) [provisioner](https://smallstep.com/docs/step-ca/provisioners/#jwk) to use; only JWK (JSON Web Key) is supported at this time.

#### `STEP_PROVISIONER_PASSWORD_FILE`

File with the password for the Smallstep CA provisioner specified in `STEP_PROVISIONER`.

#### `STEP_SECRETS`

The path used for Smallstep CA secret files (e.g., private keys and P12 files), defaults to `${STEPPATH}/secrets`.

### Django Settings

#### `CACHE_URL`

Defaults to `None`.

#### `CACHE_BACKEND`

Defaults to `django.core.cache.backends.redis.RedisCache`; only valid when the `CACHE_URL` setting is provided.

#### `CSRF_COOKIE_AGE`

Defaults to the value of `SESSION_COOKIE_AGE`.

#### `CSRF_COOKIE_DOMAIN`

Defaults to the value of `SESSION_COOKIE_DOMAIN`.

#### `CSRF_COOKIE_HTTPONLY`

Defaults to `False`.

#### `CSRF_COOKIE_NAME`

Defaults to `openmapscsrf`.

#### `CSRF_COOKIE_PATH`

Defaults to the value of `SESSION_COOKIE_PATH`.

#### `CSRF_COOKIE_SAMESITE`

Defaults to the value of `SESSION_COOKIE_SAMESITE`.

#### `CSRF_COOKIE_SECURE`

Defaults to `False`.

#### `CSRF_TRUSTED_ORIGINS`

Defaults to `[]`.

#### `CSRF_USE_SESSIONS`

Defaults to `False`.

#### `DATABASE_URL`

Defaults to `sqlite:////path/to/openmaps-auth/db.sqlite3`.

#### `DEBUG`

Defaults to `True` in development, `False` in production.

#### `DJANGO_LOG_LEVEL`

The logging level to set in Django's `LOGGING` configuration; defaults to `INFO`.

#### `LANGUAGE_CODE`

Defaults to `en-us`.

#### `ROOT_URLCONF`

Defaults to `openmaps_auth.urls`.

#### `SECRET_KEY`

Please change this to a unique value in production.

#### `SECURE_PROXY_SSL_HEADER`

Defaults to `None`.

#### `SESSION_COOKIE_AGE`

Defaults to `1209600`.

#### `SESSION_COOKIE_DOMAIN`

Defaults to `None`.

#### `SESSION_COOKIE_HTTPONLY`

Defaults to `True`.

#### `SESSION_COOKIE_PATH`

Defaults to `/`.

#### `SESSION_COOKIE_SAMESITE`

Defaults to `Lax`.

#### `SESSION_COOKIE_SECURE`

Defaults to `False`.

#### `SESSION_ENGINE`

When `CACHE_URL` is set, defaults to `django.contrib.sessions.backends.cache`; `django.contrib.sessions.backends.db` otherwise.

#### `SESSION_EXPIRE_AT_BROWSER_CLOSE`

Defaults to `False`.

#### `SESSION_FILE_PATH`

Defaults to `None`.

#### `SESSION_SAVE_EVERY_REQUEST`

Defaults to `False`.

#### `SESSION_SERIALIZER`

Defaults to `django.contrib.sessions.serializers.JSONSerializer`.

#### `SITE_ID`

Defaults to `1`.

#### `STATIC_ROOT`

Defaults to `/path/to/openmaps-auth/static`.

#### `STATIC_URL`

Defaults to `{OPENMAPS_AUTH_BASE_PATH}/static/`.

#### `TIME_ZONE`

Defaults to `UTC`.

#### `USE_I18N`

Defaults to `True`.

#### `USE_L10N`

Defaults to `True`.

#### `USE_TZ`

Defaults to `True`.

#### `USE_X_FORWARDED_HOST`

Defaults to `False`.

#### `USE_X_FORWARDED_PORT`

Defaults to `False`.
