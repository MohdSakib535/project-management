"""
URL configuration for projectManagement project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from base.views import UserViewSet, ProjectViewSet, TaskViewSet, CommentViewSet

# Main router
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'projects', ProjectViewSet, basename='project')
router.register(r'tasks', TaskViewSet, basename='task')
router.register(r'comments', CommentViewSet, basename='comment')

# Nested routers for project->tasks
projects_router = routers.NestedDefaultRouter(router, r'projects', lookup='project')
projects_router.register(r'tasks', TaskViewSet, basename='project-tasks')

# Nested routers for task->comments
tasks_router = routers.NestedDefaultRouter(router, r'tasks', lookup='task')
tasks_router.register(r'comments', CommentViewSet, basename='task-comments')

# Create URL patterns for our API endpoints
urlpatterns = [
    path('admin/', admin.site.urls),
    # API endpoints using routers
    path('api/', include(router.urls)),
    path('api/', include(projects_router.urls)),
    path('api/', include(tasks_router.urls)),
    
    # User registration and login endpoints
    path('api/users/register/', UserViewSet.as_view({'post': 'register'}), name='user-register'),
    path('api/users/login/', UserViewSet.as_view({'post': 'login'}), name='user-login'),

    #all-projects endpoint
    path('api/projects/all/', UserViewSet.as_view({'get': 'all'}), name='all_project'),
    
    # Project add_member endpoint
    path('api/projects/<int:pk>/add_member/', ProjectViewSet.as_view({'post': 'add_member'}), name='project-add-member'),
    
    # Authentication URLs (for browser login during development)
    path('api-auth/', include('rest_framework.urls')),
]