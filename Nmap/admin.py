from django.contrib import admin

# Register your models here.
from .models import (
    Project,
    Range,
    Host,
    OperativeSystemMatch,
    OperativeSystemClass,
    Port,
    PortService,
    ScannerHistory,
    Sub_Domain
)
admin.register(Project)(admin.ModelAdmin)
admin.register(Range)(admin.ModelAdmin)
admin.register(Host)(admin.ModelAdmin)
admin.register(OperativeSystemMatch)(admin.ModelAdmin)
admin.register(OperativeSystemClass)(admin.ModelAdmin)
admin.register(Port)(admin.ModelAdmin)
admin.register(PortService)(admin.ModelAdmin)
admin.register(ScannerHistory)(admin.ModelAdmin)
admin.register(Sub_Domain)(admin.ModelAdmin)