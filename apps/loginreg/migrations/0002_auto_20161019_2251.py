# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-10-19 22:51
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('loginreg', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='pw_hash',
            field=models.CharField(max_length=255),
        ),
    ]