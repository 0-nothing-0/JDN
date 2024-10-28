from django.urls import include, path
from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    path(r'admin/', admin.site.urls),
    path(r'', include('forum.urls')),
    path('paper/', include('paper.urls')),
    path('eccv/', include('eccv.urls')),
    path('iclr/', include('iclr.urls')),
    path('sp/', include('sp.urls')),
]
