# OpenMaps Authentication API

This application enables authentication integrations for Maxar's OpenMapping environments.
Specifically, this provides a simple API for mediating access to a private OpenStreetMap
instance via external identity providers.

## Configuration Reference

All listed setting may be set via an environment variable of the same name.

### Application Settings

* `OPENMAPS_AUTH_APP_LINKS`
* `OPENMAPS_AUTH_BASE_PATH`
* `OPENMAPS_AUTH_BACKEND`
* `OPENMAPS_AUTH_KEY`
* `OPENMAPS_AUTH_REDIRECT_URI`
* `OPENMAPS_AUTH_SECRET`
* `OPENMAPS_AUTH_SECRET_FILE`
* `OPENMAPS_AUTH_TITLE`
* `OPENMAPS_AUTH_WHITELISTED_DOMAINS`
* `OPENMAPS_AUTH_WHITELISTED_EMAILS`
* `OPENMAPS_AUTH_WHITELISTED_EMAILS_FILE`


### Django Settings

* `CACHE_URL`
* `DATABASE_URL`: Defaults `sqlite:////path/to/openmaps-auth/db.sqlite3`.
* `DEBUG`
