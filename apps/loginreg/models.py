from __future__ import unicode_literals
import re, bcrypt
from django.core.exceptions import ObjectDoesNotExist
from django.db import models

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class UserManager(models.Manager):
    # Create list of errors to be used for validation, initialize as empty list
    def validation_errors(self, request):
        errors = []
        # Check length of first and last names
        if len(request.POST['first_name']) < 3 or len(request.POST['last_name']) < 3:
            errors.append("First and last name must be longer than three characters.")
        # Check that the email is in the correct format
        if not EMAIL_REGEX.match(request.POST['email']):
            errors.append("Must use valid email")
        # Check that password length is long enough, and matches the confirm password
        if len(request.POST['password']) < 8 or request.POST['password'] != request.POST['pwconfirm']:
            errors.append("Passwords must match and be at least 8 characters")
        # Return the list of errors in a list, to be displayed on the main page
        return errors

    def reg_validation(self, request):
        # Refer back to the validation_error function
        errors = self.validation_errors(request)
        # If there are any errors, return those errors instead of moving on
        if len(errors) > 0:
            return (False, errors)
        # If there are no errors, hash the password using Bcrypt, then add user to database
        pw_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = self.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], pw_hash=pw_hash)
        return (True, user)

    def login_validation(self, request):
        # Check if user email and password are in database, and if they match
        try:
            user = User.objects.get(email=request.POST['email'])
            password = request.POST['password'].encode()
            if bcrypt.hashpw(password, user.pw_hash.encode()):
                return (True, user)
        # If neither exist, just return false automatically. If one of these returns false, return the same result to keep confidentiality
        except ObjectDoesNotExist:
            pass
        return (False, ["Email/password don't match those in the database"])

class User(models.Model):
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    email = models.CharField(max_length=60)
    pw_hash = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()
