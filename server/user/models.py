from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone
import random
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **kwargs):
        if not email:
            raise ValueError("Email is required")
        
        email = self.normalize_email(email)
        user = self.model(
            email=email,
            first_name=kwargs.get("first_name", ""),
            last_name=kwargs.get("last_name", ""),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **kwargs):
        kwargs.setdefault("is_staff", True)
        kwargs.setdefault("is_superuser", True)
        kwargs.setdefault("is_active", True)

        if kwargs.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if kwargs.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **kwargs)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, verbose_name="email address")
    first_name = models.CharField(max_length=50, verbose_name="first name")
    last_name = models.CharField(max_length=50, verbose_name="last name")
    is_active = models.BooleanField(default=False, verbose_name="is active")
    is_staff = models.BooleanField(default=False, verbose_name="is staff")
    is_superuser = models.BooleanField(default=False, verbose_name="is superuser")
    otp = models.CharField(max_length=6, null=True, blank=True, verbose_name="OTP")
    otp_expires_at = models.DateTimeField(null=True, blank=True, verbose_name="OTP expiration")

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.otp_expires_at = timezone.now() + timezone.timedelta(minutes=5)
        self.save()

    def verify_otp(self, otp):
        if self.otp == otp and self.otp_expires_at > timezone.now():
            self.is_active = True
            self.otp = None
            self.otp_expires_at = None
            self.save()
            return True
        return False

    def clean(self):
        if not self.email:
            raise ValidationError("Email is required")
        if not self.first_name:
            raise ValidationError("First name is required")
        if not self.last_name:
            raise ValidationError("Last name is required")

class Profile(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE, verbose_name="user")
    image = models.ImageField(upload_to="profile/", default="media/profile/avatar.png", verbose_name="profile image")
    about = models.TextField(blank=True, null=True, verbose_name="about")

    def __str__(self):
        return f"{self.user.email} Profile"

    def clean(self):
        if not self.user:
            raise ValidationError("User is required")

@receiver(post_save, sender=get_user_model())
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=get_user_model())
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, 'profile'):
        instance.profile.save()
