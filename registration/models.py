from django.db import models
import datetime, random, sha, re
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.utils.translation import ugettext as _
from django.conf import settings
from apps.location.models import Country,State,City
from django.shortcuts import _get_queryset
GENDER_CHOICES = (
    ('Male', 'Male'),
    ('Female', 'Female'),
    
)

class AppUserManager(BaseUserManager):



    

    def verify_user(self, verification_key):
        """
        Given the activation key, makes a User's account active if the
        activation key is valid and has not expired.
        
        Returns the User if successful, or False if the account was
        not found or the key had expired.
        
        """
        # Make sure the key we're trying conforms to the pattern of a
        # SHA1 hash; if it doesn't, no point even trying to look it up
        # in the DB.
        if re.match('[a-f0-9]{40}', verification_key):
            try:
                maker = self.get(verification_key=verification_key)
            except self.model.DoesNotExist:
                return False
            if not maker.verification_key_expired():
                # Account exists and has a non-expired key. Activate it.
                
                maker.is_verified = True
                maker.save()
                return maker
            if maker:
                return maker
            return False









class AppUser(AbstractBaseUser):
	first_name = models.CharField(verbose_name = _('First Name'), max_length=50)
	last_name = models.CharField(verbose_name = _('Last Name'), max_length=50)
	email = models.EmailField(verbose_name = _('Email'),max_length=254, unique=True)
	phone = models.CharField(verbose_name = _('Phone'), max_length=10,null=True,blank=True)
	age = models.CharField(verbose_name = _('Age'), max_length=50,null=True,blank=True)
	date_of_birth = models.DateField(verbose_name = _('Date of Birth'), max_length=50,null=True,blank=True)
	gender = models.CharField(choices=GENDER_CHOICES,verbose_name=_('Gender'),max_length=100)
	avatar = models.ImageField(upload_to='uploads/member',verbose_name = _('Avatar'),null=True,blank=True)
	house_name = models.CharField(verbose_name = _('House Name'), max_length=50,null=True,blank=True)
	country = models.ForeignKey(Country,verbose_name = _('Country'),null=True,blank=True)
	state = models.ForeignKey(State,verbose_name = _('State'),null=True,blank=True)
	city = models.ForeignKey(City,verbose_name = _('City'),null=True,blank=True)
	zip_code = models.CharField(verbose_name = _('Pin code'), max_length=50,null=True,blank=True)
	is_employer = models.BooleanField(default=False,verbose_name = _('is employer'))
	is_employee = models.BooleanField(default=False,verbose_name = _('is employee'))
	is_admin = models.BooleanField(default=False,verbose_name = _('is admin'))
	verification_key = models.CharField(max_length=40)
	key_generated = models.DateTimeField()
	is_verified = models.BooleanField(default=False)
	email_varify = models.BooleanField(default=False)
	phone_varify = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	objects = AppUserManager()

      
        
	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['email']
     
    

	def get_child_model(self):
		"""
           Attempts to determine if an inherited model record exists.
           New child relationships can be added though the inner class Inheritance.
           class Model(ChildAwareModel):
                ...

                class Inheritance:
                    children = ( 'yourapp.models.ChildModel', )
           """

		def get_child_module(module, list):
			if len(list) > 1:
				return get_child_module(getattr(module, list[0:1][0]), list[1:])
			else:
				return getattr(module, list[0])

		if hasattr(self, 'Inheritance'):
			children = getattr(self.Inheritance, 'children', [])
			for c in children:
				components = c.split('.')
				m = __import__(components[0])
				klass = get_child_module(m, components[1:])
				qs = _get_queryset(klass)
				try:
					child = qs.get( **{ 'pk':self.pk } )
					return child
				except qs.model.DoesNotExist:
					pass
		return None
        
	class Inheritance:
		children = (
		
			)

	def has_perm(self, perm, obj=None):
		"Does the user have a specific permission?"
		return True


	def has_module_perms(self, app_label):
		"Does the user have permissions to view the app `app_label`?"
		return True


	@property
	def is_staff(self):
		"Is the user a member of staff?"
		return self.is_admin

	def save(self, *args, **kwargs):
		if not self.id:
			self.key_generated = timezone.now()
              
           

			salt = sha.new(str(random.random())).hexdigest()[:5]
			verification_key = sha.new(salt+self.email).hexdigest()

                
			self.verification_key = verification_key
			self.set_unusable_password()
			self.is_verified=False
			subject = "Activate your account"
			print self.email
			html_content = render_to_string('registration/mail/welcome.html', { 'first_name':self.first_name,
																	'last_name':self.last_name,
																'site_url': settings.SITE_URL, 
                                                               'verification_key': verification_key,
                                                                'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS })
			text_content = strip_tags(html_content)
                                   # create the email, and attach the HTML version as well.
			msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_TO, to=[self.email])
			msg.attach_alternative(html_content, "text/html")
			msg.send()
		super(AppUser, self).save(*args, **kwargs)
    
    
    
	def verification_key_expired(self):
            
		expiration_date = datetime.timedelta(days=30)
		return self.key_generated + expiration_date <= timezone.now()


    