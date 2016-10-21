from __future__ import unicode_literals
import datetime
from django.db import models
from ..loginreg.models import User
class TripManager(models.Manager):

    def tripval(self, data):
        errors=[]
        if data['dest']=="" or data['descript']=='':
            errors.append("You cannot have blank fields. Please enter a Destination and Description")
        if data['date_from']<datetime.datetime.now().strftime('%Y-%m-%d'):
            errors.append('You cant travel into the past.... Or can you......')
        if data['date_to']<data['date_from']:
            errors.append('You must travel fowards in time. Pick a later "To" Date.')
        return errors
    def createplan (self, data, user):
        self.create(destination=data['dest'], decription=data['descript'],date_from=data['date_from'], date_to=data['date_to'], me=User.objects.get(id=user))
    def join(self,trip_id,user_id):
        self.get(id=trip_id,).groupie.add(user_id)
# Create your models here.
class Trip(models.Model):
    destination = models.CharField(max_length=200)
    decription = models.CharField(max_length=255)
    date_to = models.DateField()
    date_from = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    me=models.ForeignKey(User)
    groupie=models.ManyToManyField(User, related_name="group")
    objects=TripManager()
