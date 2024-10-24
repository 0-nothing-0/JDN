from celery import shared_task
import requests
from bs4 import BeautifulSoup
from .models import Paper

@shared_task
def fetch_papers():
    print("开始执行爬虫任务")
    url = "https://eprint.iacr.org/"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    entries = soup.find_all('h6', class_='mb-0')
    for entry in entries:
        a_tag = entry.find('a')
        if a_tag:
            paper_id = a_tag.text.strip()
            paper_link = 'https://eprint.iacr.org/' + a_tag['href']

            authors_div = entry.find_next_sibling('div', class_='fst-italic mt-0')
            authors = authors_div.text.strip() if authors_div else "Unknown"

            # 打印爬取的论文信息
            print(paper_id, paper_link, authors)
            # 保存或更新数据库记录
            Paper.objects.update_or_create(
                paper_id=paper_id,
                defaults={
                    'title': paper_id,  # 假设标题和编号相同
                    'link': paper_link,
                    'authors': authors
                }
            )
