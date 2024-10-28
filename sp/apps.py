from django.apps import AppConfig
from myforum.celery import app
from datetime import datetime

class EccvConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sp'