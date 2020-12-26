from django.db import models


class User(models.Model):
    name = models.CharField(max_length=50)
    surname = models.CharField(max_length=50)
    age = models.IntegerField(default=0)
    gender = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    role = models.CharField(max_length=50)
    password = models.CharField(max_length=100)
    user_photo = models.ImageField(upload_to="upload/user", null=True)


class Student(models.Model):
    name = models.CharField(max_length=50)
    surname = models.CharField(max_length=50)
    age = models.IntegerField(default=0)
    gender = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=100)
    user_photo = models.ImageField(upload_to="upload/student", null=True)


class Teacher(models.Model):
    name = models.CharField(max_length=50)
    surname = models.CharField(max_length=50)
    age = models.IntegerField(default=0)
    gender = models.CharField(max_length=50)


class Lesson(models.Model):
    name = models.CharField(max_length=50)
    teacher = models.ForeignKey(Teacher, on_delete=models.CASCADE)
    student = models.ManyToManyField(Student, through="Score")


class Score(models.Model):
    score = models.IntegerField(default=0)
    student = models.ForeignKey(Student, on_delete=models.CASCADE)
    lesson = models.ForeignKey(Lesson, on_delete=models.CASCADE)