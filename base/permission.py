from base.models import *
from rest_framework import viewsets, status, permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner
        return obj.owner == request.user


class IsProjectAdmin(permissions.BasePermission):
    """
    Custom permission to only allow project admins to perform certain actions.
    """
    def has_permission(self, request, view):
        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return False
            
        try:
            membership = ProjectMember.objects.get(project_id=project_id, user=request.user)
            return membership.role == 'Admin'
        except ProjectMember.DoesNotExist:
            return False


class IsProjectMember(permissions.BasePermission):
    """
    Custom permission to only allow project members to access project resources.
    """
    def has_permission(self, request, view):
        project_id = view.kwargs.get('project_pk') or request.data.get('project')
        if not project_id:
            return False
            
        try:
            ProjectMember.objects.get(project_id=project_id, user=request.user)
            return True
        except ProjectMember.DoesNotExist:
            return False
   


class IsProjectOrTaskMember(permissions.BasePermission):
    """
    Custom permission that allows access to:
    - Project members
    - Task assignees (for task & comment-related actions)
    """

    def has_permission(self, request, view):
        """Checks if the user is authenticated before deeper object-level checks."""
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        """
        Checks if the user is either:
        - A member of the project's team
        - The assigned user of the task
        """

        # Handle different object types
        if isinstance(obj, Comment):
            task = obj.task  
        elif isinstance(obj, Task):
            task = obj  
        elif hasattr(obj, "project"): 
            return ProjectMember.objects.filter(
                project=obj, user=request.user
            ).exists()
        else:
            return False  
        
        is_project_member = ProjectMember.objects.filter(
            project=task.project, user=request.user
        ).exists()

        is_task_assignee = task.assigned_to == request.user

        return is_project_member or is_task_assignee
