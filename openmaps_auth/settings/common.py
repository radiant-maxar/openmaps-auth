from pathlib import Path
from django.core.exceptions import ImproperlyConfigured
import environ

env = environ.FileAwareEnv()

BASE_DIR = Path(__file__).parent.parent.parent
BASE_PATH = env.str("OPENMAPS_AUTH_BASE_PATH", default="")

OPENMAPS_AUTH_BACKEND = env.str("OPENMAPS_AUTH_BACKEND", default=None)
if OPENMAPS_AUTH_BACKEND:
    OPENMAPS_AUTH_REDIRECT_URI = env.str("OPENMAPS_AUTH_REDIRECT_URI")
    OPENMAPS_AUTH_SECRET = env.str("OPENMAPS_AUTH_SECRET", default="")
OPENMAPS_AUTH_TITLE = env.str("OPENMAPS_AUTH_TITLE", default="Maxar OpenMaps")
OPENMAPS_AUTH_APP_LINKS = env.json(
    "OPENMAPS_AUTH_APP_LINKS", default=[{"link": "/", "text": "MapEdit"}]
)
OPENMAPS_AUTH_CLIENT_TLS = env.bool("OPENMAPS_AUTH_CLIENT_TLS", default=False)
OPENMAPS_AUTH_CLIENT_TLS_CERT_HEADER = env.bool(
    "OPENMAPS_AUTH_CLIENT_TLS_CERT_HEADER", default="X-TLS-Client-Cert"
)
OPENMAPS_AUTH_CLIENT_TLS_VERIFY_HEADER = env.bool(
    "OPENMAPS_AUTH_CLIENT_TLS_VERIFY_HEADER", default="X-TLS-Client-Verify"
)
OPENMAPS_AUTH_OSM_SESSION = env.bool("OPENMAPS_AUTH_OSM_SESSION", default=False)

OSM_BASE_URL = env.str("OSM_BASE_URL", default="https://www.openstreetmap.org")
OSM_AUTH_URL = env.str("OSM_AUTH_URL", default=OSM_BASE_URL)
OSM_SESSION_KEY = env.str("OSM_SESSION_KEY", default="_osm_session")
OSM_USER_PASSWORD = env.str("OSM_USER_PASSWORD", default="changemenow")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["*"])
DEBUG = env.bool("DEBUG", default=False)
SECRET_KEY = env.str(
    "SECRET_KEY",
    default="django-insecure-$#zokn+#tb4^z-k@l32umk&d=3299qoc%b@z@^23+3mh&4i##g",
)
SITE_ID = env.int("SITE_ID", default=1)

# Application definition
INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "social_django",
    "openmaps_auth",
)

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

if OPENMAPS_AUTH_CLIENT_TLS:
    MIDDLEWARE.append("openmaps_auth.tls.TLSClientMiddleware")

ROOT_URLCONF = env.str("ROOT_URLCONF", default="openmaps_auth.urls")

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "social_django.context_processors.backends",
                "social_django.context_processors.login_redirect",
                "openmaps_auth.context_processors.settings",
            ],
        },
    },
]

WSGI_APPLICATION = env.str("WSGI_APPLICATION", default="openmaps_auth.wsgi.application")

# Database
DATABASES = {
    "default": env.db_url(
        "DATABASE_URL", default="sqlite:///{}".format(BASE_DIR / "db.sqlite3")
    ),
}

# Cache
CACHE_URL = env.cache_url(
    default=None,
    backend=env.str(
        "CACHE_BACKEND", "django.core.cache.backends.memcached.PyMemcacheCache"
    ),
)
if CACHE_URL:
    CACHES = {"default": CACHE_URL}
    DEFAULT_SESSION_ENGINE = "django.contrib.sessions.backends.cache"
else:
    DEFAULT_SESSION_ENGINE = "django.contrib.sessions.backends.db"

# Sessions
SESSION_COOKIE_AGE = env.int("SESSION_COOKIE_AGE", default=1209600)
SESSION_COOKIE_DOMAIN = env.str("SESSION_COOKIE_DOMAIN", default=None)
SESSION_COOKIE_NAME = env.str("SESSION_COOKIE_NAME", default="openmapsid")
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=False)
SESSION_ENGINE = env.str("SESSION_ENGINE", default=DEFAULT_SESSION_ENGINE)

# CSRF
CSRF_COOKIE_NAME = env.str("CSRF_COOKIE_NAME", default="openmapscsrf")
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=SESSION_COOKIE_SECURE)
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[])

# Authentication
OPENMAPS_AUTH_KEY = env.str("OPENMAPS_AUTH_KEY", default="")
OPENMAPS_AUTH_OIDC_ENDPOINT = env.str("OPENMAPS_AUTH_OIDC_ENDPOINT", default=None)

# Always have fallback model backend.
AUTHENTICATION_BACKENDS = ("django.contrib.auth.backends.ModelBackend",)
if OPENMAPS_AUTH_CLIENT_TLS:
    AUTHENTICATION_BACKENDS = AUTHENTICATION_BACKENDS + (
        "openmaps_auth.tls.TLSClientBackend",
    )

# Set up social_auth variables when backend is set.
if OPENMAPS_AUTH_BACKEND == "login-gov":
    AUTHENTICATION_BACKENDS = (
        "openmaps_auth.backends.LoginGovOpenIdConnect",
    ) + AUTHENTICATION_BACKENDS
    SOCIAL_AUTH_LOGIN_GOV_KEY = OPENMAPS_AUTH_KEY
    SOCIAL_AUTH_LOGIN_GOV_SECRET = OPENMAPS_AUTH_SECRET
    SOCIAL_AUTH_LOGIN_GOV_REDIRECT_URI = OPENMAPS_AUTH_REDIRECT_URI
    if OPENMAPS_AUTH_OIDC_ENDPOINT:
        SOCIAL_AUTH_LOGIN_GOV_OIDC_ENDPOINT = OPENMAPS_AUTH_OIDC_ENDPOINT
elif OPENMAPS_AUTH_BACKEND == "okta-openidconnect":
    AUTHENTICATION_BACKENDS = (
        "openmaps_auth.backends.OktaOpenIdConnect",
    ) + AUTHENTICATION_BACKENDS
    SOCIAL_AUTH_OKTA_OPENIDCONNECT_KEY = OPENMAPS_AUTH_KEY
    SOCIAL_AUTH_OKTA_OPENIDCONNECT_SECRET = OPENMAPS_AUTH_SECRET
    SOCIAL_AUTH_OKTA_OPENIDCONNECT_REDIRECT_URI = OPENMAPS_AUTH_REDIRECT_URI
    if OPENMAPS_AUTH_OIDC_ENDPOINT:
        SOCIAL_AUTH_OKTA_OPENIDCONNECT_API_URL = OPENMAPS_AUTH_OIDC_ENDPOINT
    else:
        raise ImproperlyConfigured("Must provide endpoint for Okta")
elif OPENMAPS_AUTH_BACKEND == "openstreetmap":
    AUTHENTICATION_BACKENDS = (
        "openmaps_auth.backends.OpenStreetMapOAuth",
    ) + AUTHENTICATION_BACKENDS
    SOCIAL_AUTH_OPENSTREETMAP_KEY = OPENMAPS_AUTH_KEY
    SOCIAL_AUTH_OPENSTREETMAP_SECRET = OPENMAPS_AUTH_SECRET
    SOCIAL_AUTH_OPENSTREETMAP_REDIRECT_URI = OPENMAPS_AUTH_REDIRECT_URI

# Username is email address.
SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True

# Ensure proper redirects when using email or social login.
LOGIN_REDIRECT_URL = "callback"
LOGOUT_REDIRECT_URL = "index"
SOCIAL_AUTH_LOGIN_REDIRECT_URL = "index"

# When using social or tls login, restrict access based on email or domain
# whitelists if they are defined.
OPENMAPS_AUTH_WHITELISTED_DOMAINS = env.list(
    "OPENMAPS_AUTH_WHITELISTED_DOMAINS", default=[]
)
SOCIAL_AUTH_WHITELISTED_DOMAINS = OPENMAPS_AUTH_WHITELISTED_DOMAINS
OPENMAPS_AUTH_WHITELISTED_EMAILS = env.list(
    "OPENMAPS_AUTH_WHITELISTED_EMAILS", default=[]
)
SOCIAL_AUTH_WHITELISTED_EMAILS = OPENMAPS_AUTH_WHITELISTED_EMAILS

# Only use scrypt and pbkdf2 for password hashes.
PASSWORD_HASHERS = (
    "django.contrib.auth.hashers.ScryptPasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
)

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": env.str("DJANGO_LOG_LEVEL", default="INFO"),
            "propagate": True,
        },
        "openmaps_auth": {
            "handlers": ["console"],
            "level": env.str("OPENMAPS_AUTH_LOG_LEVEL", default="INFO"),
            "propagate": True,
        },
    },
}

# Internationalization
LANGUAGE_CODE = env.str("LANGUAGE_CODE", default="en-us")
TIME_ZONE = env.str("TIME_ZONE", default="UTC")
USE_I18N = env.bool("USE_I18N", default=True)
USE_TZ = env.bool("USE_TZ", default=True)

# Static files (CSS, JavaScript, Images)
STATIC_URL = env.str("STATIC_URL", default=f"{BASE_PATH}static/")
