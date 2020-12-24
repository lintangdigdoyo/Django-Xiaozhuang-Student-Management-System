from django.shortcuts import redirect, render
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from .models import User
from django.http import HttpResponseRedirect

import jwt
import bcrypt
import datetime


def login(request):
    if request.method == "GET":
        return render(request, "student_management/login.html")

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            context = {"warning": "Invalid credentials"}
            return render(request, "student_management/login.html", context)

        if check_bcrypt(password, user.password):
            response = HttpResponseRedirect(reverse("student_management:dashboard"))
            fullname = f"{user.name} {user.surname}"

            token = encode_jwt(username, fullname, user.role)
            response.set_cookie("access_token", token, 24 * 60 * 60)

            return response
        else:
            context = {"warning": "Invalid credentials"}
            return render(request, "student_management/login.html", context)


def logout(request):
    response = HttpResponseRedirect(reverse("student_management:login"))
    response.delete_cookie("access_token")
    return response


def dashboard(request):
    if request.method == "GET":
        auth_user = auth(request)
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }

            return render(request, "student_management/dashboard.html", context)
        else:
            return redirect(reverse("student_management:login"))


# ---USER---


def list_user(request):
    if request.method == "GET":
        auth_user = auth(request)
        if auth_user:
            users = User.objects.all()
            context = {
                "users": users,
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }
            return render(request, "student_management/user/user.html", context)
        else:
            return redirect(reverse("student_management:login"))


def add_user(request):
    if request.method == "GET":
        auth_user = auth(request)
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }
            return render(request, "student_management/user/add_user.html", context)
        else:
            return redirect(reverse("student_management:login"))

    if request.method == "POST":
        auth_user = auth(request)

        user = User()
        name = request.POST.get("name")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")
        username = request.POST.get("username")
        role = request.POST.get("role")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        user_photo = request.FILES.get("photo")

        print(user_photo)

        count = 0
        for a in username:
            if (a.isspace()) == True:
                count += 1

        if count > 0:
            context = {"warning": "Space not allowed in username"}
            return render(request, "student_management/user/add_user.html", context)

        if confirm_password == password:
            password = hash_bcrypt(password)

            user.name = name.lower()
            user.surname = surname.lower()
            user.age = age
            user.gender = gender
            user.username = username
            user.role = role
            user.password = password
            user.user_photo = user_photo
            user.save()

            context = {
                "success": "User added successfully",
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }
            return render(request, "student_management/user/add_user.html", context)
        elif confirm_password != password:
            context = {
                "warning": "Password not match",
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }
            return render(request, "student_management/user/add_user.html", context)


def delete_user(request):
    if request.method == "POST":
        userId = request.POST.get("delete_user")
        user = User.objects.get(pk=userId)
        user.delete()
        return redirect(reverse("student_management:list_user"))


# ---Student---


def list_student(request):
    if request.method == "GET":
        auth_user = auth(request)
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }
            return render(request, "student_management/student/student.html", context)
        else:
            return redirect(reverse("student_management:login"))


def add_student(request):
    if request.method == "GET":
        auth_user = auth(request)
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
            }
            return render(
                request, "student_management/student/add_student.html", context
            )
        else:
            return redirect(reverse("student_management:login"))


def hash_bcrypt(password):
    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def check_bcrypt(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def encode_jwt(username, fullname, role):
    return jwt.encode(
        {
            "username": username,
            "fullname": fullname,
            "role": role,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        },
        "w2cQz2v2TTyabnGHTybmtVlxVriaje6gg6Vztr24tL5eT90t",
        algorithm="HS256",
    ).decode("utf-8")


def decode_jwt(encoded_token):
    return jwt.decode(
        encoded_token,
        "w2cQz2v2TTyabnGHTybmtVlxVriaje6gg6Vztr24tL5eT90t",
        algorithm="HS256",
    )


def auth(request):
    token = request.COOKIES.get("access_token")
    try:
        auth_user = decode_jwt(token)
        return auth_user
    except jwt.exceptions.ExpiredSignatureError:
        return False
    except jwt.exceptions.DecodeError:
        return False