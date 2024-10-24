from django.urls import path
from .views import papers_list  

urlpatterns = [
    path('', papers_list, name='papers_list'),
]
