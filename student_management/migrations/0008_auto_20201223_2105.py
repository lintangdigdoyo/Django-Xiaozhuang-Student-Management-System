# Generated by Django 3.1.2 on 2020-12-23 14:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student_management', '0007_auto_20201223_2014'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='photo',
        ),
        migrations.AddField(
            model_name='user',
            name='user_photo',
            field=models.ImageField(null=True, upload_to='static/upload'),
        ),
    ]
