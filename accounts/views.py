from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import login, logout
from django.utils import timezone
from .models import CustomUser
from .serializers import (
    UserSerializer, LoginSerializer, RegisterSerializer, 
    ChangePasswordSerializer
)

class LoginView(generics.GenericAPIView):
    """Vista para login de usuarios"""
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        # Actualizar last_login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Crear o obtener token
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data,
            'message': 'Login exitoso'
        }, status=status.HTTP_200_OK)

class RegisterView(generics.CreateAPIView):
    """Vista para registro de usuarios"""
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Crear token para el usuario
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'token': token.key,
            'user': UserSerializer(user).data,
            'message': 'Usuario registrado exitosamente'
        }, status=status.HTTP_201_CREATED)

class LogoutView(generics.GenericAPIView):
    """Vista para logout"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request, *args, **kwargs):
        try:
            # Eliminar token
            request.user.auth_token.delete()
            return Response({
                'message': 'Logout exitoso'
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': 'Error al cerrar sesión'
            }, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(generics.RetrieveUpdateAPIView):
    """Vista para obtener y actualizar perfil del usuario"""
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        return self.request.user

class ChangePasswordView(generics.UpdateAPIView):
    """Vista para cambiar contraseña"""
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    
    def get_object(self):
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = self.get_object()
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        return Response({
            'message': 'Contraseña actualizada exitosamente'
        }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_token(request):
    """Verificar si el token es válido"""
    return Response({
        'valid': True,
        'user': UserSerializer(request.user).data
    })