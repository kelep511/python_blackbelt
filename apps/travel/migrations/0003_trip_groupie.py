# -*- coding: utf-8 -*-
# Generated by Django 1.10.2 on 2016-10-21 19:10
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('loginreg', '0002_auto_20161019_2251'),
        ('travel', '0002_auto_20161021_1846'),
    ]

    operations = [
        migrations.AddField(
            model_name='trip',
            name='groupie',
            field=models.ManyToManyField(related_name='group', to='loginreg.User'),
        ),
    ]
