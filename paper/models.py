from django.db import models

class Paper(models.Model):
    paper_id = models.CharField(max_length=100, unique=True)
    title = models.CharField(max_length=500)
    authors = models.TextField()
    link = models.URLField()

    def __str__(self):
        return self.title





