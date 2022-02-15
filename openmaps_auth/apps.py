from django.apps import AppConfig


class OpenMapsAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "openmaps_auth"
    verbose_name = "OpenMaps Auth"

    def ready(self):
        from . import signals
