from django.contrib.auth import authenticate
from rest_framework.response import Response  # Add this
from rest_framework import status  # Add this
from rest_framework.decorators import api_view, permission_classes  # Add this
from rest_framework.permissions import AllowAny
from django.conf import settings
from django.middleware import csrf
from rest_framework import (
    exceptions as rest_exceptions,
    response,
    decorators as rest_decorators,
    permissions as rest_permissions,
    status,  # Import status for HTTP status codes
)
from rest_framework.decorators import api_view, permission_classes  # Import api_view and permission_classes
from rest_framework_simplejwt import (
    tokens,
    views as jwt_views,
    serializers as jwt_serializers,
    exceptions as jwt_exceptions,
)
from user import serializers, models
from django.middleware.csrf import get_token
from django.core.mail import send_mail
from .models import User  # Import User model

@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([])
def get_csrf_token(request):
    return response.Response({"csrfToken": get_token(request)})

def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token),
    }

@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([])
def loginView(request):
    serializer = serializers.LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data["email"]
    password = serializer.validated_data["password"]

    user = authenticate(email=email, password=password)

    if user is not None:
        tokens = get_user_tokens(user)
        res = response.Response()
        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE"],
            value=tokens["access_token"],
            expires=settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.set_cookie(
            key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
            value=tokens["refresh_token"],
            expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
            secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
            httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
            samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
        )

        res.data = tokens
        res["X-CSRFToken"] = csrf.get_token(request)
        return res
    raise rest_exceptions.AuthenticationFailed("Email or Password is incorrect!")

from django.core.mail import send_mail
from django.conf import settings


@api_view(['POST'])
@permission_classes([AllowAny])
def registerView(request):
    try:
        step = request.data.get('step')
        email = request.data.get('email')
        
        if not email:
            return Response({'detail': 'Email required'}, status=status.HTTP_400_BAD_REQUEST)

        if step == 1:
            User.objects.get_or_create(
                email=email,
                defaults={
                    'first_name': request.data.get('first_name', ''),
                    'last_name': request.data.get('last_name', '')
                }
            )
            return Response({'message': 'Proceed to step 2'})

        elif step == 2:
            user = User.objects.get(email=email)
            user.set_password(request.data['password'])
            user.generate_otp()
            send_mail(
                "Your Verification Code",
                f"Your OTP: {user.otp}",
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False
            )
            return Response({'message': 'OTP sent'})

        elif step == 3:
            user = User.objects.get(email=email)
            if user.verify_otp(request.data.get('otp')):
                return Response({'message': 'Registration complete'})
            return Response({'detail': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'detail': 'Invalid step'}, status=status.HTTP_400_BAD_REQUEST)

    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@rest_decorators.api_view(["POST"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def logoutView(request):
    try:
        refreshToken = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        token = tokens.RefreshToken(refreshToken)
        token.blacklist()

        res = response.Response()
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE"])
        res.delete_cookie(settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"])
        res.delete_cookie("X-CSRFToken")
        res.delete_cookie("csrftoken")
        res["X-CSRFToken"] = None

        return res
    except:
        raise rest_exceptions.ParseError("Invalid token")

class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs["refresh"] = self.context["request"].COOKIES.get("refresh")
        if attrs["refresh"]:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken("No valid token found in cookie 'refresh'")

class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT["AUTH_COOKIE_REFRESH"],
                value=response.data["refresh"],
                expires=settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"],
                secure=settings.SIMPLE_JWT["AUTH_COOKIE_SECURE"],
                httponly=settings.SIMPLE_JWT["AUTH_COOKIE_HTTP_ONLY"],
                samesite=settings.SIMPLE_JWT["AUTH_COOKIE_SAMESITE"],
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)

@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def user(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    serializer = serializers.UserSerializer(user)
    return response.Response(serializer.data)
