from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Project, ProjectMember, Task, Comment

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    list_filter = ('is_staff', 'is_active', 'date_joined')

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'owner', 'created_at')
    search_fields = ('name', 'description', 'owner__username')
    list_filter = ('created_at',)
    date_hierarchy = 'created_at'

@admin.register(ProjectMember)
class ProjectMemberAdmin(admin.ModelAdmin):
    list_display = ('project', 'user', 'role')
    search_fields = ('project__name', 'user__username')
    list_filter = ('role',)

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'project', 'status', 'priority', 'assigned_to', 'due_date')
    search_fields = ('title', 'description', 'project__name', 'assigned_to__username')
    list_filter = ('status', 'priority', 'created_at', 'due_date')
    date_hierarchy = 'created_at'

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('task','content', 'user', 'created_at')
    search_fields = ('content', 'task__title', 'user__username')
    list_filter = ('created_at',)
    date_hierarchy = 'created_at'