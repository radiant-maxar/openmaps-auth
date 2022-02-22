# OpenMaps Authentication API

This application enables authentication integrations for Maxar's OpenMapping environments. Specifically, this provides a simple API for mediating access to a private OpenStreetMap instance via external identity providers.

## Requirements

* Python 3.7+
* OpenStreetMap instance, either public or private.
* OAuth or OIDC credentials when using an identity provider.

## Configuration Reference

All listed setting may be set via an environment variable of the same name, or by using a file with the setting's contents and appending `_FILE` to the setting name.

### Application Settings

#### `OPENMAPS_AUTH_APP_LINKS`

A JSON list of applications used when generating links on the index; defaults to: `{"link": "/", "text": "MapEdit"}`

#### `OPENMAPS_AUTH_BASE_PATH`

Base path for all URLs, default is the empty string (`""`).

#### `OPENMAPS_AUTH_BACKEND`

Authentication backend to use, defaults to `None`.  Set this to the desired external identity provider:

* `login-gov`
* `openstreetmap`

The following must also be configured when setting a backend:

* `OPENMAPS_AUTH_KEY`
* `OPENMAPS_AUTH_SECRET`
* `OPENMAPS_AUTH_REDIRECT_URI`

#### `OPENMAPS_AUTH_KEY`

The OAuth consumer key or OIDC client identifier when using a social authentication backend.

#### `OPENMAPS_AUTH_OIDC_ENDPOINT`

Set this to change OIDC endpoint URL from the default.

#### `OPENMAPS_AUTH_REDIRECT_URI`

The redirect URI for use by the identity provider, e.g.: `http://localhost:8880/index`.

#### `OPENMAPS_AUTH_SECRET`

The OAuth consumer secret or OIDC private RSA key in PEM format.

#### `OPENMAPS_AUTH_TITLE`

The title to use in the generated pages, defaults to `Maxar OpenMaps`.

#### `OPENMAPS_AUTH_WHITELISTED_DOMAINS`

#### `OPENMAPS_AUTH_WHITELISTED_EMAILS`

#### OSM_BASE_URL

Base URL to access OpenStreetMap at, defaults to `https://www.openstreetmap.org`.

#### OSM_AUTH_URL

Base URL for accessing OpenStreetMap authentication endpoints, defaults to the value of `OSM_BASE_URL`.

#### OSM_SESSION_KEY

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

#### `DATABASE_URL`

Defaults to `sqlite:////path/to/openmaps-auth/db.sqlite3`.

#### `DEBUG`

Defaults to `True` in development, `False` in production.

#### `LANGUAGE_CODE`

Defaults to `en-us`.

#### `LOG_LEVEL`

The logging level to set in Django's `LOGGING` configuration; defaults to `INFO`.

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
