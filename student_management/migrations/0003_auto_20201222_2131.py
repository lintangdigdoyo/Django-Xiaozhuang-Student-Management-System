# Generated by Django 3.1.2 on 2020-12-22 14:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student_management', '0002_remove_user_department'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=100),
        ),
    ]
