# coding:utf-8
import datetime

from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db.models import signals
from django.urls import reverse_lazy
import os
import uuid
# Create your models here.

#每个模型被表示为 django.db.models.Model 类的子类。
#每个模型有许多类变量，它们都表示模型里的一个数据库字段。
#每个字段都是 Field 类的实例 - 比如，字符字段被表示为 CharField ，日期时间字段被表示为 DateTimeField 。这将告诉 Django 每个字段要处理的数据类型。
#每个 Field 类实例变量的名字（例如 levels 或 avatar）也是字段名，所以最好使用对机器友好的格式。你将会在 Python 代码里使用它们，而数据库会将它们作为列名。
def avatar_upload_to(instance, filename):
    # 使用 UUID 生成唯一文件名，保持原始文件扩展名
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return os.path.join('avatars', filename)

        
class LoginUser(AbstractUser):
    levels = models.PositiveIntegerField(default=0, verbose_name=u'积分')
    avatar = models.ImageField(
        upload_to=avatar_upload_to, default='avatars/default.png', verbose_name='头像'
    )
    privilege = models.CharField(max_length=200, default=0, verbose_name=u'权限')
    friends = models.ManyToManyField(
        'self', blank=True, null=True, related_name='friends')

    class Meta:
        db_table = 'loginuser'
        verbose_name_plural = u'用户'
        ordering = ['-date_joined']

    def __str__(self):
        return self.get_username()

    def checkfriend(self, username):
        if username in self.friends.all():
            return True
        else:
            return False
    def get_like_url(self):
        return reverse_lazy('user_like')
    def user_post(self):
        return Post.objects.filter(author=self)
    def remove_friend(self, friend):
        """移除好友"""
        if friend in self.friends.all():
            self.friends.remove(friend)
            return True
        return False


class Nav(models.Model):
    name = models.CharField(max_length=40, verbose_name=u'导航条')
    url = models.CharField(
        max_length=200, blank=True, null=True, verbose_name=u'指向地址')
    create_time = models.DateTimeField(
        u'创建时间', auto_now_add=True)

    class Meta:
        db_table = 'nav'
        verbose_name_plural = verbose_name = u"导航条"
        ordering = ['-create_time']

    def __str__(self):
        return self.name


class Column(models.Model):  # 板块
    name = models.CharField(max_length=30)
    #我们使用 ForeignKey 定义了一个关系。这将告诉 Django，每个 Choice 对象都关联到一个 Question 对象。
    #Django 支持所有常用的数据库关系：多对一、多对多和一对一。
    manager = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='column_manager', on_delete=models.PROTECT)  # 版主
    parent = models.ForeignKey(
        'self', blank=True, null=True, related_name='childcolumn', on_delete=models.PROTECT)
    description = models.TextField()
    img = models.CharField(
        max_length=200, default='/default/default.png', verbose_name=u'图标')
    post_number = models.IntegerField(default=0)  # 主题数
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'column'
        ordering = ['-post_number']
        verbose_name_plural = u'板块'

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse_lazy('column_detail', kwargs={"column_pk": self.pk})


class PostType(models.Model):  # 文章类型
    type_name = models.CharField(max_length=30)
    description = models.TextField()
    created_at = models.DateTimeField(default=datetime.datetime.now)

    class Meta:
        db_table = 'posttype'
        verbose_name_plural = u'主题类型'

    def __str__(self):
        return self.type_name
    #给模型增加 __str__() 方法是很重要的，这不仅仅能给你在命令行里使用带来方便，Django 自动生成的 admin 里也使用这个方法来表示对象。

class Post(models.Model):  # 文章
    title = models.CharField(max_length=30)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='post_author', on_delete=models.PROTECT)  # 作者
    column = models.ForeignKey(Column, on_delete=models.PROTECT)  # 所属板块    settings.AUTH_USER_MODEL, related_name='post_author', on_delete=models.PROTECT)  # 作者
    
    type_name = models.ForeignKey(PostType, on_delete=models.PROTECT)  # 文章类型
    content = models.TextField()

    view_times = models.IntegerField(default=0)  # 浏览次数
    responce_times = models.IntegerField(default=0)  # 回复次数
    last_response = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)  # 最后回复者

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'post'
        ordering = ['-created_at']
        verbose_name_plural = u'主题'

    def __str__(self):
        return self.title

    def description(self):
        return u'%s 发表了主题《%s》' % (self.author, self.title)

    def get_absolute_url(self):
        return reverse_lazy('post_detail', kwargs={"post_pk": self.pk})

    def get_like_url(self):
        return reverse_lazy('add_to_favorites', kwargs={"post_pk": self.pk})
    
    def delete_like_url(self):
        return reverse_lazy('remove_from_favorites', kwargs={"post_pk": self.pk})
    
class Lrelation(models.Model):
    user = models.ForeignKey(LoginUser, on_delete=models.PROTECT,related_name='user_relations')  # 所属板块
    post = models.ForeignKey(Post, on_delete=models.PROTECT)  # 所属板块
    
    class Meta:
        db_table = 'Lrelation'
        verbose_name_plural = u'收藏'

class Comment(models.Model):  # 评论
    post = models.ForeignKey(Post, on_delete=models.PROTECT)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    comment_parent = models.ForeignKey(
        'self', blank=True, null=True, related_name='childcomment', on_delete=models.PROTECT)
    content = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'comment'
        ordering = ['created_at']
        verbose_name_plural = u'评论'

    def __str__(self):
        return self.content

    def description(self):
        return u'%s 回复了您的帖子(%s):%s' % (self.author, self.post, self.content)

    def get_absolute_url(self):
        return reverse_lazy('post_detail', kwargs={"post_pk": self.post.pk})
    
    def get_like_url(self):
        return reverse_lazy('add_to_favorites', kwargs={"post_pk": self.pk})


class Message(models.Model):  # 好友消息
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='message_sender', on_delete=models.PROTECT)  # 发送者
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='message_receiver', on_delete=models.PROTECT)  # 接收者
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def description(self):
        return u'%s 发送消息：%s' % (self.sender, self.content)

    class Meta:
        db_table = 'message'
        verbose_name_plural = u'消息'


class Application(models.Model):  # 好友申请
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='appli_sender', on_delete=models.PROTECT)  # 发送者
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='appli_receiver', on_delete=models.PROTECT)  # 接收者
    status = models.IntegerField(default=0)  # 申请状态 0:未查看 1:同意 2:不同意
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def description(self):
        return u'%s 申请添加 %s 为好友' % (self.sender,self.receiver)

    class Meta:
        db_table = 'application'
        verbose_name_plural = u'好友申请'


class Notice(models.Model):
    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='notice_sender', on_delete=models.PROTECT)  # 发送者
    receiver = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='notice_receiver', on_delete=models.PROTECT)  # 接收者
    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.PositiveIntegerField()
    event = GenericForeignKey('content_type', 'object_id')

    status = models.BooleanField(default=False)  # 是否阅读
    type = models.IntegerField()  # 通知类型 0:评论 1:好友消息 2:好友申请
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'notice'
        ordering = ['-created_at']
        verbose_name_plural = u'通知'

    def __str__(self):
        description = self.description()
        if len(description) > 40:
            return description[:40] + '...'  # 截断并添加省略号
        return description

    def description(self):
        if self.event:
            return self.event.description()
        return "No Event"

    def reading(self):
        if not status:
            status = True


def post_save(sender, instance, signal, *args, **kwargs):
    entity = instance
    if str(entity.created_at)[:19] == str(
            entity.updated_at)[:19]:  # 第一次发帖操作，编辑不操作
        column = entity.column
        column.post_number += 1
        column.save()


def post_delete(sender, instance, signal, *args, **kwargs):  # 删帖触发板块帖子数减1
    entity = instance
    column = entity.column
    column.post_number -= 1
    column.save()


def comment_save(sender, instance, signal, *args, **kwargs):
    entity = instance
    if str(entity.created_at)[:19] == str(entity.updated_at)[:19]:
        if entity.author != entity.post.author:  # 作者的回复不给作者通知
            event = Notice(
                sender=entity.author,
                receiver=entity.post.author,
                event=entity,
                type=0)
            event.save()
        if entity.comment_parent is not None:  # 回复评论给要评论的人通知
            if entity.author.id != entity.comment_parent.author.id:  # 自己给自己写评论不通知
                event = Notice(
                    sender=entity.author,
                    receiver=entity.comment_parent.author,
                    event=entity,
                    type=0)
                event.save()


def application_save(sender, instance, signal, *args, **kwargs):
    entity = instance
    if str(entity.created_at)[:19] == str(entity.updated_at)[:19]:
        event = Notice(
            sender=entity.sender,
            receiver=entity.receiver,
            event=entity,
            type=1)
        event.save()


def message_save(sender, instance, signal, *args, **kwargs):
    entity = instance
    if str(entity.created_at)[:19] == str(entity.updated_at)[:19]:
        event = Notice(
            sender=entity.sender,
            receiver=entity.receiver,
            event=entity,
            type=2)
        event.save()

# 消息响应函数注册
signals.post_save.connect(comment_save, sender=Comment)
signals.post_save.connect(application_save, sender=Message)
signals.post_save.connect(message_save, sender=Application)
signals.post_save.connect(post_save, sender=Post)
signals.post_delete.connect(post_delete, sender=Post)

