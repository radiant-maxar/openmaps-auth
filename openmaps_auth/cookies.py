from django.conf import settings


def set_auth_cookies(request, response):
    if settings.OPENMAPS_AUTH_OSM_SESSION:
        response.set_cookie(
            settings.OSM_SESSION_KEY,
            request.session[settings.OSM_SESSION_KEY],
            domain=settings.SESSION_COOKIE_DOMAIN,
        )
    return response
