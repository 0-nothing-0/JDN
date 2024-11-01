# coding:utf-8
import os
import time
import logging
import random #changed

from io import BytesIO
from django.http import JsonResponse
from django.shortcuts import render
from django.shortcuts import redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse #changed
from django.http.response import Http404
from django.views.generic import ListView, DetailView
from django.views.generic.edit import CreateView, UpdateView, DeleteView, FormView
from forum.models import Nav, Post, Comment, Application, LoginUser, Notice, Column, Message,Lrelation

from forum.form import MessageForm, PostForm, LoginUserForm
from django.urls import reverse_lazy

from django.urls import reverse #changed
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.db.models import Q
from django.utils.timezone import now, timedelta
from django.core.cache import cache

from forum.validate import create_validate_code

from paper.models import Paper as eprint
from eccv.models import Paper as Eccvs
from iclr.models import Paper as Iclrs
from sp.models import Paper as SPs
import json




logger = logging.getLogger(__name__)

PAGE_NUM = 50

#每个视图必须要做的只有两件事：
#返回一个包含被请求页面内容的 HttpResponse 对象，或者抛出一个异常，比如 Http404 。至于你还想干些什么，随便你。
    
def view_eprints(request):
    papers = eprint.objects.all().order_by('-id')[:8]
    emojis = ['😀', '😂', '🤔', '😍', '👍', '💥', '📘', '🔬']
    # Add random emoji to each paper
    papers_with_emojis = [(paper, random.choice(emojis)) for paper in papers]
    return render(request, 'papers/paper.html', {'papers_with_emojis': papers_with_emojis})

def view_eccvs(request):
    papers = Eccvs.objects.all().order_by('-id')[3:10]
    emojis = ['😀', '😂', '🤔', '😍', '👍', '💥', '📘', '🔬']
    papers_with_emojis = [(paper, random.choice(emojis)) for paper in papers]
    return render(request, 'eccv/eccv.html', {'papers_with_emojis': papers_with_emojis})

def view_iclrs(request):
    papers = Iclrs.objects.all().order_by('-id')[3:10]
    emojis = ['😀', '😂', '🤔', '😍', '👍', '💥', '📘', '🔬']
    papers_with_emojis = [(paper, random.choice(emojis)) for paper in papers]
    return render(request, 'iclr/iclr.html', {'papers_with_emojis': papers_with_emojis})


def view_sps(request):
    papers = SPs.objects.all().order_by('-id')[3:10]
    emojis = ['😀', '😂', '🤔', '😍', '👍', '💥', '📘', '🔬']
    papers_with_emojis = [(paper, random.choice(emojis)) for paper in papers]
    return render(request, 'sp/sp.html', {'papers_with_emojis': papers_with_emojis})


def get_online_ips_count():
    """统计当前在线人数（5分钟内，中间件实现于middle.py）"""
    online_ips = cache.get("online_ips", [])
    if online_ips:
        online_ips = cache.get_many(online_ips).keys()
        return len(online_ips)
    return 0


def get_forum_info():
    """获取 论坛信息，贴子数，用户数，昨日发帖数，今日发帖数"""
    # 请使用缓存
    oneday = timedelta(days=1)
    today = now().date()
    lastday = today - oneday
    todayend = today + oneday
    post_number = Post.objects.count()
    account_number = LoginUser.objects.count()

    lastday_post_number = cache.get('lastday_post_number', None)
    today_post_number = cache.get('today_post_number', None)

    if lastday_post_number is None:
        lastday_post_number = Post.objects.filter(
            created_at__range=[lastday, today]).count()
        cache.set('lastday_post_number', lastday_post_number, 60 * 60)

    if today_post_number is None:
        today_post_number = Post.objects.filter(
            created_at__range=[today, todayend]).count()
        cache.set('today_post_number', today_post_number, 60 * 60)

    info = {
        "post_number": post_number,
        "account_number": account_number,
        "lastday_post_number": lastday_post_number,
        "today_post_number": today_post_number
    }
    return info


def userlogin(request, template_name='login.html'):
    """用户登录"""
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        next = request.POST['next']

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            user.levels += 1  # 登录一次积分加 1
            user.save()
            return HttpResponseRedirect(next)
        else:
            error_message = "用户名或密码错误"
            return render(request, template_name, {'next': next, 'error_message': error_message})
    else:
        next = request.GET.get('next', None)
        if next is None:
            next = reverse_lazy('index')
        return render(request, template_name, {'next': next})


def userlogout(request):
    """用户注销"""
    logout(request)
    return HttpResponseRedirect(reverse_lazy('index'))


def userregister(request):
    """用户注销"""
    if request.method == 'POST':
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        password_confirm = request.POST.get("password_confirm", "")
        email = request.POST.get("email", "")

        form = LoginUserForm(request.POST)
        errors = []
        # 验证表单是否正确
        if form.is_valid():
            current_site = get_current_site(request)
            site_name = current_site.name
            domain = current_site.domain
            title = u"欢迎来到 %s ！" % site_name
            message = u"你好！ %s ,感谢注册 %s ！\n\n" % (username, site_name) + \
                      u"请牢记以下信息：\n" + \
                      u"用户名：%s" % username + "\n" + \
                      u"邮箱：%s" % email + "\n" + \
                      u"网站：http://%s" % domain + "\n\n"
            from_email = None
            try:
                send_mail(title, message, from_email, [email])
            except Exception as e:
                logger.error(
                    u'用户注册邮件发送失败:username: %s, email: %s' % (username, email), exc_info=True)
                return HttpResponse(u"发送邮件错误!\n注册失败", status=500)

            new_user = form.save()
            user = authenticate(username=username, password=password)
            login(request, user)
        else:
            # 如果表单不正确,保存错误到errors列表中
            for k, v in form.errors.items():
                # v.as_text() 详见django.forms.util.ErrorList 中
                errors.append(v.as_text())

        return render(request, 'user_ok.html', {"errors": errors})

    else:
        # next = request.GET.get('next',None)
        # if next is None:
        # next = reverse_lazy('index')
        return render(request, 'register.html')

def confirm_delete_account(request):
    """显示确认删除用户账户的页面"""
    if request.method == 'POST':
        if 'confirm' in request.POST:
            user = request.user
            user.delete()
            logout(request)
            return HttpResponseRedirect(reverse('index'))
        elif 'cancel' in request.POST:
            return HttpResponseRedirect(reverse('index'))
    
    response_html = """
    <html>
        <head>
            <title>确认注销</title>
        </head>
        <body>
            <p>是否确定注销用户？</p>
            <form method="post">
                {% csrf_token %}
                <button type="submit" name="confirm">确定</button>
                <button type="submit" name="cancel">取消</button>
            </form>
        </body>
    </html>
    """
    return HttpResponse(response_html)

def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST.get("email", "")
        new_password = request.POST.get("new_password", "")
        confirm_password = request.POST.get("confirm_password", "")
        verification_code = request.POST.get("verification_code", "")
        
        user = LoginUser.objects.filter(email=email).first()
        errors = []

        if user:
            if request.POST.get('resend_code'):
                # 检查上次发送验证码的时间
                last_sent_time = cache.get(f"{email}_last_sent_time")
                current_time = time.time()
                if last_sent_time and current_time - last_sent_time < 60:
                    return JsonResponse({'status': 'error', 'message': '请稍后再试！每分钟只能发送一次验证码。'})
                
                # 生成6位数验证码
                verification_code = ''.join(random.choices('0123456789', k=6))
                
                # 将验证码存储在缓存中，有效期为10分钟
                cache.set(email, verification_code, 600)
                cache.set(f"{email}_last_sent_time", current_time, 600)
                
                current_site = get_current_site(request)
                domain = current_site.domain
                title = u"密码找回"
                message = u"您的验证码是：%s" % verification_code
                from_email = None
                try:
                    send_mail(title, message, from_email, [email])
                except Exception as e:
                    logger.error(
                        u'用户找回密码邮件发送失败:email: %s' % email, exc_info=True)
                    return JsonResponse({'status': 'error', 'message': '发送邮件错误！'})
                return JsonResponse({'status': 'success', 'message': '验证码已发送，请查收！'})
            else:
                # 验证验证码
                cached_code = cache.get(email)
                if cached_code != verification_code:
                    errors.append(u"验证码错误！")
                
                # 验证新密码和确认密码是否一致
                if new_password != confirm_password:
                    errors.append(u"新密码和确认密码不一致！")
                
                if not errors:
                    # 更新用户密码
                    user.set_password(new_password)
                    user.save()
                    response_html = """
                    <html>
                        <head>
                            <meta http-equiv="refresh" content="3;url={% url 'index' %}" />
                        </head>
                        <body>
                            <p>密码已成功重置！5秒后将自动跳转到主页。</p>
                            <p>如果没有跳转，点 <a href="{% url 'index' %}">这里</a> 返回主页。</p>
                        </body>
                    </html>
                    """
                    return HttpResponse(response_html)
        else:
            errors.append(u"用户不存在！")

        return render(request, 'forgot_password.html', {"errors": errors})

    else:
        return render(request, 'forgot_password.html')

def change_password(request):
    if request.method == 'POST':
        email = request.POST.get("email", "")
        new_password = request.POST.get("new_password", "")
        confirm_password = request.POST.get("confirm_password", "")
        verification_code = request.POST.get("verification_code", "")
        
        user = LoginUser.objects.filter(email=email).first()
        errors = []

        if user:
            if request.POST.get('resend_code'):
                # 检查上次发送验证码的时间
                last_sent_time = cache.get(f"{email}_last_sent_time")
                current_time = time.time()
                if last_sent_time and current_time - last_sent_time < 60:
                    return JsonResponse({'status': 'error', 'message': '请稍后再试！每分钟只能发送一次验证码。'})
                
                # 生成6位数验证码
                verification_code = ''.join(random.choices('0123456789', k=6))
                
                # 将验证码存储在缓存中，有效期为10分钟
                cache.set(email, verification_code, 600)
                cache.set(f"{email}_last_sent_time", current_time, 600)
                
                current_site = get_current_site(request)
                domain = current_site.domain
                title = u"密码修改"
                message = u"您的验证码是：%s" % verification_code
                from_email = None
                try:
                    send_mail(title, message, from_email, [email])
                except Exception as e:
                    logger.error(
                        u'用户修改密码邮件发送失败:email: %s' % email, exc_info=True)
                    return JsonResponse({'status': 'error', 'message': '发送邮件错误！'})
                return JsonResponse({'status': 'success', 'message': '验证码已发送，请查收！'})
            else:
                # 验证验证码
                cached_code = cache.get(email)
                if cached_code != verification_code:
                    errors.append(u"验证码错误！")
                
                # 验证新密码和确认密码是否一致
                if new_password != confirm_password:
                    errors.append(u"新密码和确认密码不一致！")
                
                if not errors:
                    # 使用 set_password 方法更新用户密码
                    user.set_password(new_password)
                    user.save()
                    # 注销用户并重定向到登录页面
                    logout(request)
                    login_url = reverse('user_login')
                    # 返回包含自动跳转脚本的响应
                    response_html = f"""
                    <html>
                        <head>
                            <meta http-equiv="refresh" content="5;url={login_url}" />
                        </head>
                        <body>
                            <p>密码已成功修改！5秒后将自动跳转到登录页面。</p>
                        </body>
                    </html>
                    """
                    return HttpResponse(response_html)
        else:
            errors.append(u"用户不存在！")

        return render(request, 'change_password.html', {"errors": errors})

    else:
        return render(request, 'change_password.html')

class BaseMixin(object):
    def get_context_data(self, *args, **kwargs):
        context = super(BaseMixin, self).get_context_data(**kwargs)
        try:
            context['nav_list'] = Nav.objects.all()
            context['column_list'] = Column.objects.all()[0:5]
            context['last_comments'] = Comment.objects.all().order_by(
                "-created_at")[0:10]
            if self.request.user.is_authenticated:
                k = Notice.objects.filter(
                    receiver=self.request.user, status=False).count()
                context['message_number'] = k
                context['user_posts'] = Post.objects.filter(author=self.request.user)

        except Exception as e:
            logger.error(u'[BaseMixin]加载基本信息出错', e)

        return context


class IndexView(BaseMixin, ListView):
    """首页"""
    model = Post
    queryset = Post.objects.all()
    #载入 polls/index.html 模板文件，并且向它传递一个上下文(context)。这个上下文是一个字典，它将模板内的变量映射为 Python 对象。
    template_name = 'index.html'
    context_object_name = 'post_list'
    paginate_by = PAGE_NUM  # 分页--每页的数目
        
    def get_context_data(self, **kwargs):
        kwargs['foruminfo'] = get_forum_info()
        kwargs['online_ips_count'] = get_online_ips_count()
        kwargs['hot_posts'] = self.queryset.order_by("-responce_times")[0:10]
        
        if self.request.user.is_authenticated:  # Check if the user is logged in
            user_obj = LoginUser.objects.get(username=self.request.user.username)
            like_relations = user_obj.user_relations.all()
            kwargs['like_posts'] = [like_relation.post for like_relation in like_relations]
        else:
            kwargs['like_posts'] = []  # If not authenticated, pass an empty list
        
        papers = eprint.objects.all().order_by('-id')[:8]
        kwargs['papers_list'] = papers
        
        return super(IndexView, self).get_context_data(**kwargs)

def add_to_favorites(request, post_pk):
    if request.user.is_authenticated:
        post = get_object_or_404(Post, pk=post_pk)
        Lrelation.objects.get_or_create(user=request.user, post=post)
        return_url = request.META.get('HTTP_REFERER', 'index')  # 如果没有来源则默认重定向到 'index'
    return redirect(return_url)  # 重定向回首页或其他页面

def remove_from_favorites(request, post_pk):
    if request.user.is_authenticated:
        post = get_object_or_404(Post, pk=post_pk)
        relation = Lrelation.objects.filter(user=request.user, post=post)
        if relation.exists():
            relation.delete()
        return_url = request.META.get('HTTP_REFERER', 'index')  # 如果没有来源则默认重定向到 'index'
    return redirect(return_url)

def postdetail(request, post_pk):
    """帖子详细页面"""
    post_pk = int(post_pk)
    post = Post.objects.get(pk=post_pk)
    comment_list = post.comment_set.all()
    if request.user.is_authenticated:
        k = Notice.objects.filter(receiver=request.user, status=False).count()
    else:
        k = 0
    # 统计帖子的访问访问次数
    is_favorited = Lrelation.objects.filter(user=request.user, post=post).exists() if request.user.is_authenticated else False
    
    if 'HTTP_X_FORWARDED_FOR' in request.META:
        ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.META['REMOTE_ADDR']
    title = post.title
    visited_ips = cache.get(title, [])

    if ip not in visited_ips:
        post.view_times += 1
        post.save()
        visited_ips.append(ip)
    cache.set(title, visited_ips, 15 * 60)
    return render(request, 'post_detail.html', {
        'post': post,
        'comment_list': comment_list,
        'message_number': k,
        'is_favorited': is_favorited
    })


def makefriend(request, sender, receiver):
    """加好友"""
    sender = LoginUser.objects.get(username=sender)
    receiver = LoginUser.objects.get(username=receiver)
    application = Application(sender=sender, receiver=receiver, status=0)
    application.save()
    return HttpResponse(
        """
        <script type="text/javascript">
            alert("已向%s成功发送申请！");
            window.history.back(); 
        </script>
        """ % (receiver)
    )


@login_required(login_url=reverse_lazy('user_login'))
def shownotice(request):
    """消息通知"""
    notice_list = Notice.objects.filter(receiver=request.user, status=False)
    myfriends = LoginUser.objects.get(username=request.user).friends.all()
    User_obj = LoginUser.objects.get(username=request.user)
    user_posts = Post.objects.filter(author=request.user)
    like_relations = User_obj.user_relations.all()
    like_posts = [like_relation.post for like_relation in like_relations] 
    return render(request, 'notice_list.html', {
        'user': User_obj,
        'notice_list': notice_list,
        'myfriends': myfriends,
        'user_posts':user_posts,
        'like_posts':like_posts
    })
#「载入模板，填充上下文，再返回由它生成的 HttpResponse 对象」是一个非常常用的操作流程。
# 于是 Django 提供了一个快捷函数（render），我们用它来重写 index() 视图：

# def noticedetail(request, pk):
#     """具体通知"""
#     pk = int(pk)
#     notice = Notice.objects.get(pk=pk)
#     notice.status = True
#     notice.save()
#     if notice.type == 0:  # 评论通知
#         post_id = notice.event.post.id
#         return HttpResponseRedirect(
#             reverse_lazy('post_detail', kwargs={"post_pk": post_id}))
#     message_id = notice.event.id  # 消息通知
#     return HttpResponseRedirect(
#         reverse_lazy('message_detail', kwargs={"pk": message_id}))
def noticedetail(request, pk):
    """具体通知"""
    pk = int(pk)
    notice = Notice.objects.get(pk=pk)
    notice.status = True
    notice.save()

    if notice.type == 0:  # 评论通知
        post_id = notice.event.post.id
        return HttpResponseRedirect(
            reverse_lazy('post_detail', kwargs={"post_pk": post_id})
        )
    elif notice.type == 1:  # 消息通知
        message = notice.event  # 假设 event 是 Message 实例
        data = {
            'sender': message.sender.username,
            'content': message.content,
            "sender_id": message.sender.id,  # 确保 sender_id 包含在数据中
            'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        return JsonResponse(data)  # 返回消息数据，前端处理显示模态窗口

    return HttpResponseRedirect('/')  # 默认跳转到首页

class MessageDetail(DetailView):
    """具体消息"""
    model = Message
    template_name = 'message.html'
    context_object_name = 'message'

def friendagree(request, pk, flag):
    """好友同意/拒绝（flag 1同意，2拒绝）"""
    flag = int(flag)
    pk = int(pk)
    entity = Notice.objects.get(pk=pk)
    entity.status = True
    application = entity.event
    application.status = flag

    application.receiver.friends.add(application.sender)
    application.save()
    entity.save()

    if flag == 1:
        str = "已加好友"
    else:
        str = "拒绝加好友"
    return HttpResponse(str)


class UserPostView(ListView):
    """用户已发贴"""
    template_name = 'user_posts.html'
    context_object_name = 'user_posts'
    paginate_by = PAGE_NUM

    def get_queryset(self):
        user_posts = Post.objects.filter(author=self.request.user)
        return user_posts

class PostCreate(CreateView):
    """发帖"""
    model = Post
    template_name = 'form.html'
    form_class = PostForm
    # fields = ('title', 'column', 'type_name','content')
    # SAE django1.5中fields失效，不知原因,故使用form_class
    success_url = reverse_lazy('user_post')

    # 这里我们必须使用reverse_lazy() 而不是reverse，因为在该文件导入时URL 还没有加载。

    def form_valid(self, form):
        # 此处有待加强安全验证
        validate = self.request.POST.get('validate', None)
        formdata = form.cleaned_data
        if self.request.session.get('validate', None) != validate:
            return HttpResponse("验证码错误！<a href='/'>返回</a>")
        user = LoginUser.objects.get(username=self.request.user.username)
        # form.instance.author = user
        # form.instance.last_response  = user
        formdata['author'] = user
        formdata['last_response'] = user
        p = Post(**formdata)
        p.save()
        user.levels += 5  # 发帖一次积分加 5
        user.save()
        # return HttpResponseRedirect('/user/post_create_return/')
         # 获取帖子详情页面的 URL
        post_detail_url = reverse('post_detail', kwargs={'post_pk': p.pk})

        # 返回包含 JavaScript 的 HttpResponse
        return HttpResponse(
            f"""
            <script type="text/javascript">
                alert("发帖成功！");
                window.location.href = "{post_detail_url}";
            </script>
            """
        )

def create_return(request):
    return render(request, 'create_return.html')

class PostUpdate(UpdateView):
    """编辑贴"""
    form_class = PostForm
    model = Post
    template_name = 'form.html'
    success_url = reverse_lazy('user_post')


class PostDelete(DeleteView):
    """删贴"""
    model = Post
    template_name = 'delete_confirm.html'
    success_url = reverse_lazy('user_post')


@login_required(login_url=reverse_lazy('user_login'))
def makecomment(request):
    """评论"""
    if request.method == 'POST':
        comment = request.POST.get("comment", "")
        post_id = request.POST.get("post_id", "")
        comment_id = request.POST.get("comment_id", "")

        user = LoginUser.objects.get(username=request.user)
        p = Post.objects.get(pk=post_id)
        p.responce_times += 1
        p.last_response = user

        if comment_id:
            p_comment = Comment.objects.get(pk=comment_id)
            c = Comment(
                post=p, author=user, comment_parent=p_comment, content=comment)
            c.save()
        else:
            c = Comment(post=p, author=user, content=comment)
            c.save()
        p.save()
        user.levels += 3  # 评论一次积分加 3
        user.save()

    return HttpResponse("评论成功")


# class MessageCreate(CreateView):
#     """发送消息"""
#     model = Message
#     template_name = 'form.html'
#     form_class = MessageForm
#     # fields = ('content',)
#     # SAE django1.5中fields失效，不知原因,故使用form_class
#     success_url = reverse_lazy('show_notice')

#     def form_valid(self, form):
#         # 此处有待加强安全验证
#         sender = LoginUser.objects.get(username=self.request.user)
#         receiver_id = int(self.kwargs.get('pk'))
#         receiver = LoginUser.objects.get(id=receiver_id)
#         formdata = form.cleaned_data
#         formdata['sender'] = sender
#         formdata['receiver'] = receiver
#         m = Message(**formdata)
#         m.save()
#         return HttpResponse("消息发送成功！")
class MessageCreate(CreateView):
    """发送消息"""
    model = Message
    template_name = 'form.html'
    form_class = MessageForm
    success_url = reverse_lazy('show_notice')  # This will be used as a fallback URL

    def form_valid(self, form):
        sender = LoginUser.objects.get(username=self.request.user)
        receiver_id = int(self.kwargs.get('pk'))
        receiver = LoginUser.objects.get(id=receiver_id)
        formdata = form.cleaned_data
        formdata['sender'] = sender
        formdata['receiver'] = receiver
        m = Message(**formdata)
        m.save()
        return HttpResponse(
            """
            <script type="text/javascript">
                alert("消息发送成功！");
                window.history.go(-2);  // 返回上一个页面
            </script>
            """
        )



def columnall(request):
    """所有板块"""
    column_list = Column.objects.all()
    return render(request, 'column_list.html', {'column_list': column_list})


def columndetail(request, column_pk):
    """每个板块"""
    column_obj = Column.objects.get(pk=column_pk)
    column_posts = column_obj.post_set.all()

    return render(request, 'column_detail.html', {
        'column_obj': column_obj,
        'column_posts': column_posts
    })

def likedetail(request):
    User_obj = LoginUser.objects.get(username=request.user)
    like_relations = User_obj.user_relations.all()
    like_posts = [like_relation.post for like_relation in like_relations]
    return render(request, 'user_likes.html', {
        'user_obj': User_obj,
        'like_posts': like_posts
    })

class SearchView(ListView):
    """搜索"""
    template_name = 'search_result.html'
    context_object_name = 'results_list'
    paginate_by = PAGE_NUM

    def get_context_data(self, **kwargs):
        kwargs['q'] = self.request.GET.get('srchtxt', '')
        kwargs['search_type'] = self.request.GET.get('search_type', 'post')
        return super(SearchView, self).get_context_data(**kwargs)

    def get_queryset(self):
        # 获取搜索的关键字和搜索类型
        q = self.request.GET.get('srchtxt', '')
        search_type = self.request.GET.get('search_type', 'post')

        if search_type == 'user':
            # 在用户的用户名和邮箱中搜索
            return LoginUser.objects.filter(Q(username__icontains=q) | Q(email__icontains=q))
        else:
            # 在帖子的标题和内容中搜索
            return Post.objects.only('title', 'content').filter(Q(title__icontains=q) | Q(content__icontains=q) | Q(author__username__icontains=q))


def validate(request):
    """验证码"""
    m_stream = BytesIO()
    validate_code = create_validate_code()
    img = validate_code[0]
    img.save(m_stream, "GIF")
    request.session['validate'] = validate_code[1]
    return HttpResponse(m_stream.getvalue(), "image/gif")


def upload_image(request):
    """编辑器图片上传"""
    if request.method == 'POST':
        callback = request.GET.get('CKEditorFuncNum')
        content = request.FILES["upload"]
        file_name = "static/upload_images/" + time.strftime("%Y%m%d%H%M%S", time.localtime()) + "_" + content.name
        file_path = os.path.join(settings.BASE_DIR, file_name)

        f = open(file_path, 'wb')
        for chunk in content.chunks():
            f.write(chunk)
        f.close()
        url = '/{}'.format(file_name)

        # try:
        #     body = content.read()
        #     # 存储到object storage
        #     file_path = os.path.join('static', 'upload', content.name)
        #
        #     url = ''
        #     from os import environ
        #     online = environ.get("APP_NAME", "")
        #
        #     if online:
        #         bucket = "mystorage"
        #         import sae.storage
        #         s = sae.storage.Client()
        #         ob = sae.storage.Object(content.read())
        #         url = s.put(bucket, file_name, ob)
        #
        #     else:
        #         url = None
        #
        # except Exception as e:
        #     url = str(e)

        url = '/' + url
        res = r"<script>window.parent.CKEDITOR.tools.callFunction(" + callback + ",'" + url + "', '');</script>"
        return HttpResponse(res)
    else:
        raise Http404()

# class UserPageView(BaseMixin, ListView):
#     """用户页面视图"""
#     model = Post
#     queryset = Post.objects.all()
#     template_name = 'notice_list.html'
#     context_object_name = 'post_list'
#     paginate_by = PAGE_NUM

#     # def get_queryset(self):
#     #     user_posts = Post.objects.filter(author=self.request.user)
#     #     return user_posts
    
#     def get_context_data(self, **kwargs):
#         # 获取当前登录的用户信息
#             user_obj = LoginUser.objects.get(username=self.request.user.username)  # 当前登录用户
#             kwargs['user'] = user_obj  # 将用户对象传递到模板
#             # 获取好友列表
#             kwargs['friends'] = user_obj.friends.all()
            
#             # 用户的其他信息
#             kwargs['levels'] = user_obj.levels
#             kwargs['avatar'] = user_obj.avatar
#             kwargs['privilege'] = user_obj.privilege
#             user_posts = Post.objects.filter(author=self.request.user)
#             kwargs['user_posts'] = user_posts
#             like_relations = user_obj.user_relations.all()
#             kwargs['like_posts'] = [like_relation.post for like_relation in like_relations]        
        
#             return super(UserPageView, self).get_context_data(**kwargs)   
class UserPageView(BaseMixin, ListView):
    """用户页面视图"""
    template_name = 'notice_list.html'
    #context_object_name = 'user_posts'  # 设置上下文对象的名称
    paginate_by = PAGE_NUM  # 如果有很多帖子，可以分页

    def get_queryset(self):
        if self.request.user.is_authenticated:
            user_posts = Post.objects.filter(author=self.request.user)
            return user_posts
        else:
            return Post.objects.none()

    def get_context_data(self, **kwargs):
        # 获取基本上下文数据
        context = super(UserPageView, self).get_context_data(**kwargs)
        
        # 获取当前登录的用户信息
        if self.request.user.is_authenticated:
            user_obj = self.request.user  # 当前登录用户
            context['user'] = user_obj  # 将用户对象传递到模板
            
            # 获取好友列表
            context['friends'] = user_obj.friends.all()
            
            # 用户的其他信息
            context['levels'] = user_obj.levels
            context['avatar'] = user_obj.avatar
            context['privilege'] = user_obj.privilege
            context['like_url'] = user_obj.get_like_url()
            like_relations = user_obj.user_relations.all()
            context['like_posts'] = [like_relation.post for like_relation in like_relations]    
            # 获取用户的未读通知列表
            notice_list = Notice.objects.filter(receiver=user_obj, status=False)
            context['notice_list'] = notice_list
            notice_list_all = Notice.objects.filter(receiver=user_obj)
            context['notice_list_all'] = notice_list_all
            notice_list_send = Notice.objects.filter(sender=user_obj)
            context['notice_list_send'] = notice_list_send
            context['unread_msg_count']=notice_list.filter(type=1).count()
            context['reply_msg_count']=notice_list.filter(type=0).count()
            context['friend_msg_count']=notice_list.filter(type=2).count()
        else:
            context['user'] = None  # 如果未登录，则用户信息为 None
            context['friends'] = []  # 确保 friends 是一个空列表
            context['notice_list'] = []  # 确保 notice_list 是一个空列表
        return context


    
from PIL import Image
@login_required(login_url=reverse_lazy('user_login'))
def update_avatar(request):
    if request.method == 'POST' and request.FILES.get('avatar'):
        user = request.user
        avatar = request.FILES['avatar']
        
        # 生成新头像的文件路径，以用户名命名，并确保使用 .png 扩展名
        avatar_filename = f"{user.username}.png"
        avatar_path = os.path.join(settings.MEDIA_ROOT, 'avatars', avatar_filename)

        # 删除旧头像文件（如果存在且路径不同）
        if user.avatar.name and user.avatar.name != f"avatars/{avatar_filename}":
            old_avatar_path = os.path.join(settings.MEDIA_ROOT, user.avatar.name)
            if os.path.exists(old_avatar_path):
                os.remove(old_avatar_path)

        # 打开上传的图片文件并进行压缩和格式转换
        try:
            # 使用 Pillow 打开上传的图片
            image = Image.open(avatar)
            
            # 定义压缩的尺寸
            max_size = (300, 300)  # 最大宽高
            image.thumbnail(max_size, Image.ANTIALIAS)  # 缩小图片并保持宽高比
            
            # 转换为 RGBA 模式以支持 PNG 格式（避免因格式不支持导致的错误）
            if image.mode in ("RGBA", "P"):  # 如果图像本身有透明度
                image = image.convert("RGBA")
            else:
                image = image.convert("RGB")  # 转换为支持 PNG 的 RGB 模式

            # 保存图片为 PNG 格式
            image.save(avatar_path, format='PNG', quality=85)  # 保存为 PNG 格式

            # 更新用户的头像字段
            user.avatar.name = f"avatars/{avatar_filename}"
            user.save()

            # 上传成功后重定向到用户页面
            return redirect('show_notice')

        except Exception as e:
            print("压缩头像时出错：", e)
            return redirect('show_notice')  # 可替换为返回错误消息的页面或提示

    return redirect('show_notice')
@login_required(login_url=reverse_lazy('user_login'))
def mark_all_as_read(request):
    if request.method == 'POST':
        # 解析请求体中的 JSON 数据
        data = json.loads(request.body)
        type_param = data.get('type')

        if type_param is not None:
            # 将当前用户所有指定类型的未读消息标记为已读
            Notice.objects.filter(receiver=request.user, type=type_param, status=False).update(status=True)
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Invalid type parameter'}, status=400)

    return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)

@login_required(login_url=reverse_lazy('user_login'))
def mark_as_read(request, notice_id):
    try:
        notice = Notice.objects.get(pk=notice_id, receiver=request.user)
        notice.status = True
        notice.save()
        return JsonResponse({'success': True})
    except Notice.DoesNotExist:
        return JsonResponse({'error': 'Notice not found'}, status=404)
@login_required(login_url=reverse_lazy('user_login'))    
def remove_friend(request, friend_id):
    """删除好友"""
    user = request.user
    friend = get_object_or_404(LoginUser, id=friend_id)
    
    if user.remove_friend(friend):
        # 可以添加一条成功的消息
        return redirect('show_notice')  # 重定向到通知页面或其他页面
    else:
        # 可以添加一条错误的消息
        return redirect('show_notice')