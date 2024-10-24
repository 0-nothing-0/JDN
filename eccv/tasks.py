from celery import shared_task
from .models import Paper
import requests
from bs4 import BeautifulSoup

@shared_task
def fetch_papers():
    url = 'https://dblp.org/db/conf/eccv/eccv2024-1.html'
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to fetch data")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    papers = soup.find_all('li', class_='entry')

    for paper in papers:
        title = paper.find('span', class_='title', itemprop='name').text.strip() if paper.find('span', class_='title', itemprop='name') else '未找到标题'
        author_spans = paper.find_all('span', itemprop='author')
        authors = ', '.join([author_span.find('span', itemprop='name').text.strip() for author_span in author_spans if author_span.find('span', itemprop='name')])
        date_published = paper.find('meta', itemprop='datePublished')['content'] if paper.find('meta', itemprop='datePublished') else '未知出版日期'
        pagination = paper.find('span', itemprop='pagination').text.strip() if paper.find('span', itemprop='pagination') else '未知页码'
        doi_link = paper.find('a', href=True)['href'] if paper.find('a', href=True) else '无链接'
        # 创建或更新数据库记录
        Paper.objects.update_or_create(
            title=title,
            defaults={
                'authors': authors,
                'date_published': date_published,
                'pagination': pagination,
                'link': doi_link  # 确保模型中有 'link' 字段
            }
        )

    print(f"Total {len(papers)} papers fetched and saved/updated.")