from django.urls import path

from . import views

urlpatterns = [
    path("", views.cert_list, name="cert_list"),
    path("<uuid:pk>", views.cert_details, name="cert_details"),
    path("<uuid:pk>/delete", views.cert_delete, name="cert_delete"),
    path("<uuid:pk>/legacy", views.cert_legacy, name="cert_legacy"),
    path("<uuid:pk>/modern", views.cert_modern, name="cert_modern"),
    path("new", views.cert_new, name="cert_new"),
    path("password", views.pkcs12_password, name="pkcs12_password"),
]
