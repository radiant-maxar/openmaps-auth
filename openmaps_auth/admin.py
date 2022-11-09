from django.contrib import admin

from .models import User, Certificate


@admin.register(Certificate)
class CertificateAdmin(admin.ModelAdmin):
    list_display = ("pk", "user", "valid", "start", "end")

    @admin.display(boolean=True)
    def valid(self, obj):
        return obj.valid


admin.site.register(User)
