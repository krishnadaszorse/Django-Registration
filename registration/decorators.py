from django.http import HttpResponseRedirect
from apps.registration.models import AppUser
from apps.employee.models import Employee



def is_admin(f):
	def wrap(request, *args, **kwargs):
		try:
			userdetail=AppUser.objects.get(email= request.user)
			if not userdetail.is_administrator:
				return HttpResponseRedirect("/signout")
		except:
			return HttpResponseRedirect("/signout")
		return f(request, *args, **kwargs)
	wrap.__doc__=f.__doc__
	wrap.__name__=f.__name__
	return wrap

def is_employer(f):
	def wrap(request, *args, **kwargs):
		try:
			userdetail=AppUser.objects.get(email= request.user)
			if not userdetail.is_employer:
				return HttpResponseRedirect("/signout")
		except:
			return HttpResponseRedirect("/signout")
		return f(request, *args, **kwargs)
	wrap.__doc__=f.__doc__
	wrap.__name__=f.__name__
	return wrap
def is_employee(f):
	def wrap(request, *args, **kwargs):
		try:
			userdetail=AppUser.objects.get(email= request.user)
			if not userdetail.is_employee:
				return HttpResponseRedirect("/signout")
		except:
			return HttpResponseRedirect("/signout")
		return f(request, *args, **kwargs)
	wrap.__doc__=f.__doc__
	wrap.__name__=f.__name__
	return wrap

