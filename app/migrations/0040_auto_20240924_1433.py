# Generated by Django 2.2.27 on 2024-09-24 14:33

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0039_task_orthophoto_bands'),
    ]

    operations = [
        migrations.AlterField(
            model_name='plugindatum',
            name='user',
            field=models.ForeignKey(blank=True, default=None, help_text='The user this setting belongs to. If NULL, the setting is global.', null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, verbose_name='User'),
        ),
    ]