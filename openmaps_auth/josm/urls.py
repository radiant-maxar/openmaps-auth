from django.urls import path

from . import views

urlpatterns = [
    path(f"preferences.xml", views.preferences, name="josm_preferences"),
]
