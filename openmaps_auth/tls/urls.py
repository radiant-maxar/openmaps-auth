from django.urls import path

from . import views

urlpatterns = [
    path(f"", views.list_certs, name="list_certs"),
    path(f"<uuid:pk>", views.cert_details, name="cert_details"),
    path(f"<uuid:pk>/delete", views.delete_cert, name="delete_cert"),
    path(f"<uuid:pk>/download", views.download_cert, name="download_cert"),
    path(f"new", views.new_cert, name="new_cert"),
    path(f"password", views.pkcs12_password, name="pkcs12_password"),
]
