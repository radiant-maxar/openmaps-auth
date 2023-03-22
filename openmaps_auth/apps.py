from django.apps import AppConfig
from django.conf import settings


class OpenMapsAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "openmaps_auth"
    verbose_name = "OpenMaps Auth"

    def ready(self):
        if settings.OPENMAPS_AUTH_CLIENT_TLS:
            from .tls import signals  # noqa: F401

        if settings.OPENMAPS_AUTH_OSM_SESSION:
            from .osm import signals  # noqa: F401, F811
