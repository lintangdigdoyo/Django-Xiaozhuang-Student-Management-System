# Generated by Django 3.1.2 on 2020-12-24 15:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('student_management', '0011_student_age'),
    ]

    operations = [
        migrations.RenameField(
            model_name='student',
            old_name='firstname',
            new_name='name',
        ),
    ]