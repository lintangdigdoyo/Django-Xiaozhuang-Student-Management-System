from django.urls import path
from . import views

app_name = "student_management"
urlpatterns = [
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("", views.dashboard, name="dashboard"),
    path("edit-profile/", views.edit_profile, name="edit_profile"),
    path("user/", views.list_user, name="list_user"),
    path("user/add-user/", views.add_user, name="add_user"),
    path("user/delete-user/", views.delete_user, name="delete_user"),
    path("user/update-user/<str:username>", views.update_user, name="update_user"),
    path("student/", views.list_student, name="list_student"),
    path("student/add-student/", views.add_student, name="add_student"),
    path("student/delete-student/", views.delete_student, name="delete_student"),
    path(
        "student/update-student/<str:username>/",
        views.update_student,
        name="update_student",
    ),
    path(
        "student/<int:student_id>/add-lesson/",
        views.student_lesson,
        name="student_lesson",
    ),
    path("teacher/", views.list_teacher, name="list_teacher"),
    path("teacher/delete-teacher/", views.delete_teacher, name="delete_teacher"),
    path("teacher/add-teacher/", views.add_teacher, name="add_teacher"),
    path(
        "teacher/update-teacher/<int:teacher_id>/",
        views.update_teacher,
        name="update_teacher",
    ),
    path("lesson/", views.list_lesson, name="list_lesson"),
    path(
        "lesson/edit-lesson/<int:lesson_id>", views.update_lesson, name="update_lesson"
    ),
    path("lesson/add-lesson/", views.add_lesson, name="add_lesson"),
    path("lesson/delete-lesson/", views.delete_lesson, name="delete_lesson"),
    path(
        "lesson/detail-student/<int:lesson_id>/",
        views.detail_student,
        name="detail_student",
    ),
    path("lesson/add-score/<int:lesson_id>/", views.add_score, name="add_score"),
]
