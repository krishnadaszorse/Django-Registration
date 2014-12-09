from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from django.conf import settings
from ziksha.celery import app


@app.task
def add(x, y):
    return x + y


@app.task
def send_welcome_mail(appuser):
	subject = "Activate your account"
	html_content = render_to_string('registration/email/welcome.html', { 'site_url': settings.SITE_URL, 
                                                   'verification_key': appuser.verification_key,
                                                    'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS })
	text_content = strip_tags(html_content)
                       
	msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_TO, to=[appuser.email])
	msg.attach_alternative(html_content, "text/html")
	msg.send()
	return True
@app.task
def send_notification_mail(notification):

	subject = "New Notification : "+notification.title
	html_content = render_to_string('registration/email/notification.html', { 'site_url': settings.SITE_URL, 
                                                   'notification': notification})
	text_content = strip_tags(html_content)
                       
	msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_TO, to=[notification.app_user.email])
	msg.attach_alternative(html_content, "text/html")
	msg.send()
	return True

@app.task
def xsum(numbers):
    return sum(numbers)