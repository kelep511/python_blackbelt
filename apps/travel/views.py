from django.shortcuts import render, redirect
from .models import Trip, User
from django.contrib import messages
from django.http import HttpResponseRedirect


# Create your views here.
def index(request):
    context={
    'mytrips':Trip.objects.filter(me=User.objects.get(id=request.session['user']['id'])),
    "alltrips":Trip.objects.exclude(me=User.objects.get(id=request.session['user']['id'])).exclude(groupie=User.objects.filter(id=request.session['user']['id'])).order_by()[::-1],
    'jointrips':Trip.objects.filter(groupie=User.objects.filter(id=request.session['user']['id'])),
    'user':User.objects.filter(id=request.session['user']['id']),
    }
    return render(request,'travel/index.html', context )
def add(request):
    return render(request, "travel/add.html")
def create(request):
    validate=Trip.objects.tripval(request.POST)
    print validate
    if validate:
        for error in validate:
            messages.error(request, error)
        return redirect('travel:add')
    else:
        Trip.objects.createplan(request.POST, request.session['user']['id'])
        return redirect('travel:index')
def destination(request, id):
    context={
    'trip':Trip.objects.filter(id=id)
    }
    return render(request,'travel/destination.html',context)
def join(request, id):
    Trip.objects.join(id,request.session['user']['id'])
    return HttpResponseRedirect(request.META.get('HTTP_REFERER','/'))
