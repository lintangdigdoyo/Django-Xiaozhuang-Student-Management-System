# Generated by Django 3.1.2 on 2020-12-23 12:42

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('student_management', '0004_student'),
    ]

    operations = [
        migrations.RenameField(
            model_name='student',
            old_name='first_name',
            new_name='firstname',
        ),
    ]
