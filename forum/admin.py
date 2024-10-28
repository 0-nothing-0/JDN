from django.contrib import admin
from forum.models import LoginUser, Nav, Column, PostType, Post, Comment, Message, Application, Notice,Lrelation

# Register your models here.

#向管理页面中加入投票应用，即声明这些建立的对象需要一个后台接口
admin.site.register(LoginUser)
admin.site.register(Nav)
admin.site.register(Column)
admin.site.register(PostType)
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Message)
admin.site.register(Application)
admin.site.register(Notice)
admin.site.register(Lrelation)

#其实我们是可以引入一个类，自定义表单展示方法
#class QuestionAdmin(admin.ModelAdmin):
    #fieldsets = [
        #(None, {"fields": ["question_text"]}),
        #("Date information", {"fields": ["pub_date"]}),
    #]

#admin.site.register(Question, QuestionAdmin)

#django其实为我们的管理页面处理提供了非常多的工具
