# OpenMaps Authentication API

This application enables authentication integrations for Maxar's OpenMapping environments. Specifically, this provides a simple API for mediating access to a private OpenStreetMap instance via external identity providers.

## Requirements

* Python 3.7+
* OpenStreetMap instance, either public or private.
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

location = /v0/auth/valid {
    internal;
    proxy_pass              http://auth:8000;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
}

location / {
    proxy_pass   http://protected-app;
    auth_request /v0/auth/valid;
}
```

## Configuration Reference

All listed setting may be set via an environment variable of the same name, or by using a file with the setting's contents and appending `_FILE` to the setting name.

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

The following must also be configured when setting a backend:

* `OPENMAPS_AUTH_KEY`
* `OPENMAPS_AUTH_SECRET`
* `OPENMAPS_AUTH_REDIRECT_URI`
* `OPENMAPS_AUTH_OIDC_ENDPOINT`: when using Okta or for a Login.gov development endpoint.

#### `OPENMAPS_AUTH_CLIENT_TLS`

When set, enables authentication with TLS client certificates; requires having a certificate authority (CA), the configuration of which is beyond the scope of this document.  The [`cryptography`](https://cryptography.io/en/latest/) package is required to use this option.  Here's an example of additional [Nginx configuration](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_verify_client) to enable authentication with TLS certificates:

```
ssl_client_certificate /path/to/ca-for-clients.pem;
ssl_verify_client optional;

...

location = /v0/auth/valid {
    internal;
    proxy_pass              http://auth:8000;
    proxy_pass_request_body off;
    proxy_set_header        Content-Length "";
    proxy_set_header        X-TLS-Client-Cert $ssl_client_escaped_cert;
    proxy_set_header        X-TLS-Client-Verify $ssl_client_verify;
}

location = /v0/auth/login {
    proxy_pass       http://auth:8000;
    proxy_set_header X-TLS-Client-Cert $ssl_client_escaped_cert;
    proxy_set_header X-TLS-Client-Verify $ssl_client_verify;
}
```

#### `OPENMAPS_AUTH_CLIENT_TLS_CERT_HEADER`

HTTP header for client certifcate in PEM format, and URL encoded like Nginx's [`$ssl_client_escaped_cert`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_escaped_cert) variable; defaults to `X-TLS-Client-Cert`.

#### `OPENMAPS_AUTH_CLIENT_TLS_VERIFY_HEADER`

HTTP header for client certifcate verification status like Nginx's [`$ssl_client_verify`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#var_ssl_client_verify) variable; defaults to `X-TLS-Client-Verify`.

#### `OPENMAPS_AUTH_KEY`

The OAuth consumer key or OIDC client identifier when using a social authentication backend.

#### `OPENMAPS_AUTH_LOG_LEVEL`

The logging level for this application, defaults to `INFO`.

#### `OPENMAPS_AUTH_OIDC_ENDPOINT`

Set this to change OIDC endpoint URL from the default.

#### `OPENMAPS_AUTH_REDIRECT_URI`

The redirect URI for use by the identity provider, e.g.: `http://localhost:8880/index`.

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

#### `OSM_BASE_URL`

Base URL to access OpenStreetMap at, defaults to `https://www.openstreetmap.org`.

#### `OSM_AUTH_URL`

Base URL for accessing OpenStreetMap authentication endpoints, defaults to the value of `OSM_BASE_URL`.

#### `OSM_SESSION_KEY`

Cookie used by OpenStreetMap to store its session, defaults to [`_osm_session`](https://github.com/openstreetmap/openstreetmap-website/blob/master/config/initializers/session_store.rb#L4).

#### `OSM_USER_PASSWORD`

Password to authenticate the user to OpenStreetMap, defaults to `changemenow`.

### Django Settings

#### `CACHE_URL`

Defaults to `None`.

#### `CACHE_BACKEND`

Defaults to `django.core.cache.backends.memcached.PyMemcacheCache`; only when `CACHE_URL` is defined.

#### `CSRF_COOKIE_NAME`

Defaults to `openmapscsrf`.

#### `CSRF_COOKIE_SECURE`

Defaults to `False`.

#### `CSRF_TRUSTED_ORIGINS`

Defaults to `[]`.

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

#### `SESSION_COOKIE_AGE`

Defaults to `1209600`.

#### `SESSION_COOKIE_DOMAIN`

Defaults to `None`.

#### `SESSION_COOKIE_NAME`

Defaults to `openmapsid`.

#### `SESSION_COOKIE_SECURE`

Defaults to `False`.

#### `SECRET_KEY`

Please change this to a unique value in production.

#### `SESSION_ENGINE`

When `CACHE_URL` is set, defaults to `django.contrib.sessions.backends.cache`; `django.contrib.sessions.backends.db` otherwise.

#### `SITE_ID`

Defaults to `1`.

#### `STATIC_URL`

Defaults to `static/`.

#### `TIME_ZONE`

Defaults to `UTC`.

#### `USE_I18N`

Defaults to `True`.

#### `USE_TZ`

Defaults to `True`.
