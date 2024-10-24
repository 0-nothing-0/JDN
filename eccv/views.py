from django.shortcuts import render
from .models import Paper
import random

def papers_list(request):
    papers = Paper.objects.all().order_by('-id')[3:10]
    emojis = ['😀', '😂', '🤔', '😍', '👍', '💥', '📘', '🔬']
    papers_with_emojis = [(paper, random.choice(emojis)) for paper in papers]
    return render(request, 'eccv/eccv.html', {'papers_with_emojis': papers_with_emojis})
