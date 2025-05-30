from django.db import models

from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    mobile = models.CharField(
        max_length=13,
        unique=True,
        null=True,
    )
