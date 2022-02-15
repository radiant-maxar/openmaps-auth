from django.conf import settings as django_settings


def settings(request):
    """
    Add openmaps_auth settings to template context.
    """
    return {
        "openmaps_auth": {
            "app_links": django_settings.OPENMAPS_AUTH_APP_LINKS,
            "backend": django_settings.OPENMAPS_AUTH_BACKEND,
            "title": django_settings.OPENMAPS_AUTH_TITLE,
        }
    }
