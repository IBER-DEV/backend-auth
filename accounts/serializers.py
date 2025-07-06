from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser

class UserSerializer(serializers.ModelSerializer):
    """Serializer para información del usuario"""
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 
                 'avatar', 'phone', 'bio', 'date_joined', 'last_login')
        read_only_fields = ('id', 'date_joined', 'last_login')

class LoginSerializer(serializers.Serializer):
    """Serializer para login"""
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'})
    
    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        
        if email and password:
            user = authenticate(request=self.context.get('request'),
                              username=email, password=password)
            if not user:
                raise serializers.ValidationError(
                    'No se pudo autenticar con las credenciales proporcionadas.'
                )
            if not user.is_active:
                raise serializers.ValidationError('La cuenta de usuario está deshabilitada.')
                
            data['user'] = user
            return data
        else:
            raise serializers.ValidationError('Debe incluir email y contraseña.')

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer para registro de usuarios"""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'password_confirm',
                 'first_name', 'last_name', 'phone')
        
    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Las contraseñas no coinciden.")
        return data
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = CustomUser.objects.create_user(**validated_data)
        return user

class ChangePasswordSerializer(serializers.Serializer):
    """Serializer para cambio de contraseña"""
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('La contraseña actual es incorrecta.')
        return value
        