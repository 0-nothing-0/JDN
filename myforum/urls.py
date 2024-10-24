from django.urls import include, path
from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    #Django 管理页面
    #（创建一个能登录管理页面的用户：python manage.py createsuperuser）
    #现在，打开浏览器，转到你本地域名的 “/admin/” 目录， -- 比如 http://127.0.0.1:8000/admin/ 。你应该会看见管理员登录界面
    path(r'admin/', admin.site.urls),
    path(r'', include('forum.urls')),
    #path('papers/', include('papers.urls')),
    #path('eccv/', include('eccv.urls')),
    #path('iclr/', include('iclr.urls')),
]
