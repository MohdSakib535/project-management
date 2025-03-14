from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from .models import User, Project, ProjectMember, Task, Comment
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserSerializer,
    ProjectSerializer, ProjectMemberSerializer, TaskSerializer, CommentSerializer
)
from base.permission import IsProjectOrTaskMember,IsOwnerOrReadOnly



class UserViewSet(viewsets.ViewSet):
    """
    User ViewSet for managing user-related operations such as registration, login,
    listing, retrieving, updating, and deleting users.
    """

    def get_permissions(self):
        """
        Determine the permissions required for each action:

        - 'register' and 'login' actions: Open to all users (AllowAny)
        - 'list' and 'destroy' actions: Restricted to admin users (IsAdminUser)
        - Other actions: Require authentication (IsAuthenticated)
        """

        if self.action in ['register', 'login']:
            permission_classes = [AllowAny] 
        elif self.action in ['list', 'destroy']:  
            permission_classes = [IsAdminUser] 
        else:
            permission_classes = [IsAuthenticated]  
        return [permission() for permission in permission_classes]

    @action(detail=False, methods=['post'],authentication_classes=[])
    def register(self, request):
        """
        Register a new user and generate JWT tokens (access and refresh).
        """
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)

            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'],authentication_classes=[])
    def login(self, request):
        """
        Authenticate a user and return JWT tokens.

        Request Body:
        - username (str): User's username
        - password (str): User's password

        """
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            user = authenticate(username=username, password=password)

            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'user': UserSerializer(user).data,
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def list(self, request):
        """List all users (Admin only)"""
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        """Retrieve user details (Only self or Admins)"""
        user = get_object_or_404(User, pk=pk)
        
        if request.user != user and not request.user.is_staff:
            return Response({'error': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(user)
        return Response(serializer.data)

    def update(self, request, pk=None):
        """Update user details (Only self or Admins)"""
        user = get_object_or_404(User, pk=pk)

        if request.user != user and not request.user.is_staff:
            return Response({'error': 'You can only update your own account'}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def partial_update(self, request, pk=None):
        """Partially update user details (Only self or Admins)"""
        user = get_object_or_404(User, pk=pk)

        if request.user != user and not request.user.is_staff:
            return Response({'error': 'You can only update your own account'}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """Delete user (Admin only)"""
        user = get_object_or_404(User, pk=pk)

        if not request.user.is_staff:
            return Response({'error': 'Only admins can delete users'}, status=status.HTTP_403_FORBIDDEN)

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)




class ProjectViewSet(viewsets.ViewSet):
    """
    A viewset for handling project operations.
    """
    def get_permissions(self):
        if self.action == 'create':
            permission_classes = [IsAuthenticated]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
        elif self.action in ['list', 'retrieve','all_projects']:
            permission_classes = [IsAuthenticated]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]


    @action(detail=False, methods=['get'], url_path='all')
    def all_projects(self, request):
        """
        Custom endpoint to retrieve all projects in the system.
        Accessible only by authenticated users.
        """
        projects = Project.objects.all()
        serializer = ProjectSerializer(projects, many=True, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def list(self, request):
        user = request.user
        # Get projects where user is a member or owner
        projects = Project.objects.filter(members__user=user).distinct() | Project.objects.filter(owner=user).distinct()
        print('project-----',projects)
        serializer = ProjectSerializer(projects, many=True, context={'request': request})
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        user = request.user
        project = get_object_or_404(Project, pk=pk)
        
        # Check if user is a member or owner
        is_member = ProjectMember.objects.filter(project=project, user=user).exists()
        is_owner = project.owner == user
        
        if not (is_member or is_owner):
            return Response({'error': 'You do not have access to this project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ProjectSerializer(project, context={'request': request})
        return Response(serializer.data)
    
    def create(self, request):
        serializer = ProjectSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            project = serializer.save(owner=request.user)
            return Response(ProjectSerializer(project, context={'request': request}).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, pk=None):
        project = get_object_or_404(Project, pk=pk)
        
        # Check if user is owner
        if project.owner != request.user:
            return Response({'error': 'Only the project owner can update the project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ProjectSerializer(project, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def partial_update(self, request, pk=None):
        project = get_object_or_404(Project, pk=pk)
        
        # Check if user is owner
        if project.owner != request.user:
            return Response({'error': 'Only the project owner can update the project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ProjectSerializer(project, data=request.data, partial=True, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, pk=None):
        project = get_object_or_404(Project, pk=pk)
        
        # Check if user is owner
        if project.owner != request.user:
            return Response({'error': 'Only the project owner can delete the project'}, status=status.HTTP_403_FORBIDDEN)
        
        project.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['post'])
    def add_member(self, request, pk=None):
        project = get_object_or_404(Project, pk=pk)
        print('pro-----',project)
        
        # Check if the current user is the owner or an admin
        try:
            membership = ProjectMember.objects.get(project=project, user=request.user)
            if membership.role != 'Admin' and project.owner != request.user:
                return Response({'error': 'Only project admins can add members'}, status=status.HTTP_403_FORBIDDEN)
        except ProjectMember.DoesNotExist:
            if project.owner != request.user:
                return Response({'error': 'Only project admins can add members'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ProjectMemberSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(project=project)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TaskViewSet(viewsets.ViewSet):
    """
    A viewset for handling task operations.
    """
    def get_permissions(self):
        if self.action in ['create','list','update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated, IsProjectOrTaskMember]
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def list(self, request, project_pk=None):
        if project_pk:
            # Check if user is a project member
            try:
                ProjectMember.objects.get(project_id=project_pk, user=request.user)
            except ProjectMember.DoesNotExist:
                return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
            
            tasks = Task.objects.filter(project_id=project_pk)
        else:
            # Get tasks from all projects where user is a member
            tasks = Task.objects.filter(project__members__user=request.user)
        
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """
        Retrieve a specific task by its ID.
        """
        # Get the task by its primary key (ID)
        task = get_object_or_404(Task, pk=pk)

        # Check if the user is a member of the task's project
        if not ProjectMember.objects.filter(project=task.project, user=request.user).exists():
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)

        # Serialize and return task data
        serializer = TaskSerializer(task)
        return Response(serializer.data)
    
    def create(self, request, project_pk=None):
        if not project_pk:
            return Response({'error': 'Project ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = get_object_or_404(Project, pk=project_pk)
        
        # Check if user is a project member
        try:
            ProjectMember.objects.get(project=project, user=request.user)
        except ProjectMember.DoesNotExist:
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(project=project)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, pk=None, project_pk=None):
        if project_pk:
            task = get_object_or_404(Task, pk=pk, project_id=project_pk)
        else:
            task = get_object_or_404(Task, pk=pk)
        
        # Check if user is a project member
        try:
            ProjectMember.objects.get(project=task.project, user=request.user)
        except ProjectMember.DoesNotExist:
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TaskSerializer(task, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def partial_update(self, request, pk=None, project_pk=None):
        if project_pk:
            task = get_object_or_404(Task, pk=pk, project_id=project_pk)
        else:
            task = get_object_or_404(Task, pk=pk)
        
        # Check if user is a project member
        try:
            ProjectMember.objects.get(project=task.project, user=request.user)
        except ProjectMember.DoesNotExist:
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, pk=None, project_pk=None):
        if project_pk:
            task = get_object_or_404(Task, pk=pk, project_id=project_pk)
        else:
            task = get_object_or_404(Task, pk=pk)
        
        # Check if user is a project member
        try:
            membership = ProjectMember.objects.get(project=task.project, user=request.user)
            # Only project admins or task creator can delete tasks
            if membership.role != 'Admin' and task.project.owner != request.user:
                return Response({'error': 'Only project admins can delete tasks'}, status=status.HTTP_403_FORBIDDEN)
        except ProjectMember.DoesNotExist:
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
        
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CommentViewSet(viewsets.ViewSet):
    """
    A viewset for handling comment operations.
    """
    def get_permissions(self):
        if  self.action in ['list', 'retrieve','create']:
            permission_classes = [IsAuthenticated, IsProjectOrTaskMember]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsAuthenticated]  
        else:
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def list(self, request, task_pk=None):
        if task_pk:
            task = get_object_or_404(Task, pk=task_pk)
            
            # Check if user is a member of the task's project
            try:
                ProjectMember.objects.get(project=task.project, user=request.user)
            except ProjectMember.DoesNotExist:
                return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
            
            comments = Comment.objects.filter(task_id=task_pk)
        else:
            # Get comments from all tasks in projects where user is a member
            comments = Comment.objects.filter(task__project__members__user=request.user)
        
        serializer = CommentSerializer(comments, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None, task_pk=None):
        """
        Retrieve a specific comment by ID.
        Ensures that only project members can access the comment.
        """
        comment = get_object_or_404(Comment, pk=pk)

        # Ensure the user is a member of the comment's project
        try:
            ProjectMember.objects.get(project=comment.task.project, user=request.user)
        except ProjectMember.DoesNotExist:
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)

        serializer = CommentSerializer(comment)
        return Response(serializer.data)
    

    #only do project member or owner for particula
    def create(self, request, task_pk=None):
        if not task_pk:
            return Response({'error': 'Task ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        task = get_object_or_404(Task, pk=task_pk)
        
        # Check if user is a member of the task's project
        try:
            ProjectMember.objects.get(project=task.project, user=request.user)
        except ProjectMember.DoesNotExist:
            return Response({'error': 'You are not a member of this project'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = CommentSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(task=task, user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

    #only update self comment
    def update(self, request, pk=None, task_pk=None):
        if task_pk:
            comment = get_object_or_404(Comment, pk=pk, task_id=task_pk)
        else:
            comment = get_object_or_404(Comment, pk=pk)
        
        # Only the comment creator can update it
        if comment.user != request.user:
            return Response({'error': 'You can only update your own comments'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = CommentSerializer(comment, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def partial_update(self, request, pk=None, task_pk=None):
        if task_pk:
            comment = get_object_or_404(Comment, pk=pk, task_id=task_pk)
        else:
            comment = get_object_or_404(Comment, pk=pk)
        
        # Only the comment creator can update it
        if comment.user != request.user:
            return Response({'error': 'You can only update your own comments'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = CommentSerializer(comment, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    #delete self comment
    def destroy(self, request, pk=None, task_pk=None):
        if task_pk:
            comment = get_object_or_404(Comment, pk=pk, task_id=task_pk)
        else:
            comment = get_object_or_404(Comment, pk=pk)
        
        # Only the comment creator can delete it
        if comment.user != request.user:
            return Response({'error': 'You can only delete your own comments'}, status=status.HTTP_403_FORBIDDEN)
        
        comment.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)