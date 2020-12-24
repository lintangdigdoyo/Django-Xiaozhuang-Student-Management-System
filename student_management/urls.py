from django.urls import path
from . import views

app_name = "student_management"
urlpatterns = [
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("", views.dashboard, name="dashboard"),
    path("user/", views.list_user, name="list_user"),
    path("user/add-user/", views.add_user, name="add_user"),
    path("user/delete-user/", views.delete_user, name="delete_user"),
    path("student/", views.list_student, name="list_student"),
    path("student/add-student/", views.add_student, name="add_student"),
]
