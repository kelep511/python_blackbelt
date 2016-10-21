from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages

def index(request):
    return render(request, 'loginreg/index.html')

def register(request):
    # Return the resulting errors back from models as a stored variable
    result = User.objects.reg_validation(request)
    # If there are errors, display the error messages after redirecting to the main page
    if result[0] == False:
        print_messages(request, result[1])
        return redirect('login:index')
    # Otherwise, if there are no errors, sent the registered info to the login_success function
    return login_success(request, result[1])

def login(request):
    # Return the resulting errors back from models as a stored variable
    result = User.objects.login_validation(request)
    # If there are errors, display the error messages after redirecting to the main page
    if result[0] == False:
        print_messages(request, result[1])
        return redirect('login:index')
    # Otherwise, if there are no errors, sent the registered info to the login_success function
    return login_success(request, result[1])

def login_success(request, user):
    # Store all the login information of the logged-in user in sesion, then redirect them to the success page
    request.session['user'] = {
        'id' : user.id,
        'first_name' : user.first_name,
        'last_name' : user.last_name,
        'email' : user.email,
    }
    return redirect ('travel:index')

def print_messages(request, message_list):
    # For any error messages, add them to the error message list to be displayed on the HTML pages
    for message in message_list:
        messages.add_message(request, messages.INFO, message)

def success(request):
    # Check if the current user is in session. If not, redirect to the main page
    if not 'user' in request.session:
        return redirect('login:index')
    # Otherwise, send them to the success page
    return redirect ('travel:index')

def logout(request):
    # Knock the current user out of session
    request.session.flush()
    messages.success(request,"You logged out Successfully!")
    return redirect('login:index')
