from django.contrib import admin
from .models import AppUser



class AppUserAdmin(admin.ModelAdmin):
	model = AppUser
	exclude = ('verification_key','key_generated','is_verified','is_admin')
	list_display = ('first_name','last_name','email','phone','house_name','country','state','city',)
	list_filter = ('country','state','city')
	# search_fields = ('first_name','email')
admin.site.register(AppUser,AppUserAdmin)