from .views import *
from django.conf.urls import patterns, url

urlpatterns = patterns('',
                     
                       url(r'^verify/(?P<verification_key>\w+)/$', verify, name='verify'),
                       url(r'^re-verify/$', resend_verification ,name='re-verify'),
                       url(r'^signin/$', signin ,name='signin'),
                       # url(r'^home/$', home ,name='home'),
                       url(r'^signout/$', signout ,name='signout'),
                       url(r'^recover/(?P<signature>.+)/$', recover_done,name='password_reset_sent'),
                       url(r'^recover/$', recover, name='password_reset_recover'),
                       url(r'^reset/done/$', reset_done, name='password_reset_done'),
                       url(r'^reset/(?P<token>[\w:-]+)/$', reset,name='password_reset_reset'),
                  )

