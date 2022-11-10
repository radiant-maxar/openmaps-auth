from django.urls import path

from . import views

urlpatterns = [
    path(f"", views.cert_list, name="cert_list"),
    path(f"<uuid:pk>", views.cert_details, name="cert_details"),
    path(f"<uuid:pk>/delete", views.cert_delete, name="cert_delete"),
    path(f"<uuid:pk>/download", views.cert_download, name="cert_download"),
    path(f"new", views.cert_new, name="cert_new"),
    path(f"password", views.pkcs12_password, name="pkcs12_password"),
]
