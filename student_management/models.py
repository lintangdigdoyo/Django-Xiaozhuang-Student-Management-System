from django.db import models


class User(models.Model):
    name = models.CharField(max_length=50)
    surname = models.CharField(max_length=50)
    age = models.IntegerField(default=0)
    gender = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    role = models.CharField(max_length=50)
    password = models.CharField(max_length=100)
    user_photo = models.ImageField(upload_to="upload", null=True)


class Student(models.Model):
    firstname = models.CharField(max_length=50)
    surname = models.CharField(max_length=50)
    gender = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=100)