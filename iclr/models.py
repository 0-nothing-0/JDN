from django.db import models

class Paper(models.Model):
    title = models.CharField(max_length=500)
    authors = models.TextField()
    date_published = models.CharField(max_length=100)
    pagination = models.CharField(max_length=100)
    link = models.URLField(max_length=1000)
    
    def __str__(self):
        return self.title