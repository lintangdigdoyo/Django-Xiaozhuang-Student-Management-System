from django.shortcuts import redirect, render
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from django.http import HttpResponseRedirect
from .models import User, Student, Teacher

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
            try:
                user = Student.objects.get(username=username)
            except ObjectDoesNotExist:
                context = {"warning": "Invalid credentials"}
                return render(request, "student_management/login.html", context)

        if check_bcrypt(password, user.password):
            response = HttpResponseRedirect(reverse("student_management:dashboard"))
            fullname = f"{user.name} {user.surname}"

            if hasattr(user, "role"):
                token = encode_jwt(
                    username, fullname, user.role, f"/static/{user.user_photo}"
                )
            else:
                token = encode_jwt(
                    username, fullname, "student", f"/static/{user.user_photo}"
                )

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
                "photo": auth_user["photo"],
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
                "photo": auth_user["photo"],
            }
            return render(request, "student_management/user/user.html", context)
        else:
            return redirect(reverse("student_management:login"))


def add_user(request):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
            }
            return render(request, "student_management/user/add_user.html", context)
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
        }

        name = request.POST.get("name")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")
        username = request.POST.get("username")
        role = request.POST.get("role")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        user_photo = request.FILES.get("photo")

        try:
            findUsername = User.objects.get(username=username)
            context["warning"] = "Username already exist"
            return render(request, "student_management/user/add_user.html", context)

        except User.DoesNotExist:

            count = 0
            for a in username:
                if (a.isspace()) == True:
                    count += 1

            if count > 0:
                context["warning"] = "Space not allowed in username"
                return render(request, "student_management/user/add_user.html", context)

            if confirm_password == password:
                password = hash_bcrypt(password)

                user = User()
                user.name = name.lower()
                user.surname = surname.lower()
                user.age = age
                user.gender = gender
                user.username = username
                user.role = role
                user.password = password
                user.user_photo = user_photo
                user.save()

                context["success"] = "User added successfully"

                return render(request, "student_management/user/add_user.html", context)
            elif confirm_password != password:
                context["warning"] = "Password not match"

                return render(request, "student_management/user/add_user.html", context)


def delete_user(request):
    if request.method == "POST":
        userId = request.POST.get("delete_user")
        user = User.objects.get(pk=userId)
        user.delete()
        return redirect(reverse("student_management:list_user"))


def update_user(request, username):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            user = User.objects.get(username=username)
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
                "user": user,
            }
            return render(request, "student_management/user/edit_user.html", context)
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        user = User.objects.get(username=username)
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
            "user": user,
        }

        name = request.POST.get("name")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")
        username = request.POST.get("username")
        role = request.POST.get("role")

        try:
            if username != user.username:
                findUsername = User.objects.get(username=username)
                context["warning"] = "Username already exist"
                return render(
                    request, "student_management/user/edit_user.html", context
                )
            User.objects.get(username="")
        except User.DoesNotExist:

            count = 0
            for a in username:
                if (a.isspace()) == True:
                    count += 1

            if count > 0:
                context["warning"] = "Space not allowed in username"
                return render(
                    request, "student_management/user/edit_user.html", context
                )

            user.name = name
            user.surname = surname
            user.age = age
            user.gender = gender
            user.username = username
            user.role = role
            user.save()
            return redirect(reverse("student_management:list_user"))


# ---Student---


def list_student(request):
    if request.method == "GET":
        auth_user = auth(request)
        if auth_user:
            students = Student.objects.all()
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
                "students": students,
            }
            return render(request, "student_management/student/student.html", context)
        else:
            return redirect(reverse("student_management:login"))


def add_student(request):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
            }
            return render(
                request, "student_management/student/add_student.html", context
            )
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
        }

        name = request.POST.get("firstname")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")
        username = request.POST.get("username")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        user_photo = request.FILES.get("photo")

        try:
            findUsername = Student.objects.get(username=username)
            context["warning"] = "Username already exist"
            return render(
                request, "student_management/student/add_student.html", context
            )

        except Student.DoesNotExist:
            count = 0
            for a in username:
                if (a.isspace()) == True:
                    count += 1

            if count > 0:
                context["warning"] = "Space not allowed in username"
                return render(
                    request, "student_management/student/add_student.html", context
                )

            if confirm_password == password:
                password = hash_bcrypt(password)

                student = Student()
                student.name = name.lower()
                student.surname = surname.lower()
                student.age = age
                student.gender = gender
                student.username = username
                student.password = password
                student.user_photo = user_photo
                student.save()

                context["success"] = "Student added successfully"

                return render(
                    request, "student_management/student/add_student.html", context
                )
            elif confirm_password != password:
                context["warning"] = "Password not match"

                return render(
                    request, "student_management/student/add_student.html", context
                )


def delete_student(request):
    if request.method == "POST":
        studentId = request.POST.get("delete_student")
        student = Student.objects.get(pk=studentId)
        student.delete()
        return redirect(reverse("student_management:list_student"))


def update_student(request, username):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            student = Student.objects.get(username=username)
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
                "student": student,
            }
            return render(
                request, "student_management/student/edit_student.html", context
            )
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        student = Student.objects.get(username=username)
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
            "student": student,
        }

        name = request.POST.get("name")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")
        username = request.POST.get("username")

        try:
            if username != student.username:
                findUsername = Student.objects.get(username=username)
                context["warning"] = "Username already exist"
                return render(
                    request, "student_management/student/edit_student.html", context
                )
            Student.objects.get(username="")
        except Student.DoesNotExist:

            count = 0
            for a in username:
                if (a.isspace()) == True:
                    count += 1

            if count > 0:
                context["warning"] = "Space not allowed in username"
                return render(
                    request, "student_management/student/edit_student.html", context
                )

            student.name = name
            student.surname = surname
            student.age = age
            student.gender = gender
            student.username = username
            student.save()
            return redirect(reverse("student_management:list_student"))


# ---User Profile---


def edit_profile(request):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
            }
            return render(request, "student_management/edit_profile.html", context)
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
        }

        old_password = request.POST.get("old_password")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")
        user_photo = request.FILES.get("photo")

        if confirm_password == password:
            user = None

            if auth_user["role"] != "student":
                user = User.objects.get(username=auth_user["username"])
            else:
                user = Student.objects.get(username=auth_user["username"])

            if check_bcrypt(old_password, user.password):
                password = hash_bcrypt(password)
                print(user_photo)
                if user_photo:
                    user.user_photo = user_photo

                user.password = password
                user.save()

                context["success"] = "Profile updated successfully"
                return render(request, "student_management/edit_profile.html", context)
            else:
                context["warning"] = "Invalid password"
                return render(request, "student_management/edit_profile.html", context)

        elif confirm_password != password:
            context["warning"] = "Password not match"

            return render(request, "student_management/edit_profile.html", context)


# ---Teacher---


def list_teacher(request):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            teachers = Teacher.objects.all()
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
                "teachers": teachers,
            }

            return render(request, "student_management/teacher/teacher.html", context)
        else:
            return redirect(reverse("student_management:login"))


def add_teacher(request):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
            }

            return render(
                request, "student_management/teacher/add_teacher.html", context
            )
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
        }

        name = request.POST.get("name")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")

        teacher = Teacher()
        teacher.name = name
        teacher.surname = surname
        teacher.age = age
        teacher.gender = gender
        teacher.save()

        context["success"] = "Teacher added successfully"
        return render(request, "student_management/teacher/add_teacher.html", context)


def update_teacher(request, teacher_id):
    auth_user = auth(request)
    if request.method == "GET":
        if auth_user:
            teacher = Teacher.objects.get(id=teacher_id)
            context = {
                "username": auth_user["username"],
                "fullname": auth_user["fullname"],
                "role": auth_user["role"],
                "photo": auth_user["photo"],
                "teacher": teacher,
            }
            return render(
                request, "student_management/teacher/edit_teacher.html", context
            )
        else:
            return redirect(reverse("student_management:login"))

    elif request.method == "POST":
        teacher = Teacher.objects.get(id=teacher_id)
        context = {
            "username": auth_user["username"],
            "fullname": auth_user["fullname"],
            "role": auth_user["role"],
            "photo": auth_user["photo"],
            "teacher": teacher,
        }

        name = request.POST.get("name")
        surname = request.POST.get("surname")
        age = request.POST.get("age")
        gender = request.POST.get("gender")

        teacher.name = name
        teacher.surname = surname
        teacher.age = age
        teacher.gender = gender
        teacher.save()

        return redirect(reverse("student_management:list_teacher"))


# ---Business Logic---


def hash_bcrypt(password):
    salt = bcrypt.gensalt(rounds=10)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def check_bcrypt(password, hashed):
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def encode_jwt(username, fullname, role, photo):
    return jwt.encode(
        {
            "username": username,
            "fullname": fullname,
            "role": role,
            "photo": photo,
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