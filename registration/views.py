from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.models import RequestSite
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse, reverse_lazy
from django.core import signing
from django.core.mail import send_mail,EmailMultiAlternatives
from django.http import Http404,HttpResponseRedirect
from django.utils import timezone
from django.utils.translation import ugettext as _
from django.utils.html import strip_tags
from django.views import generic
from django.conf import settings
from django.shortcuts import render_to_response,get_object_or_404,redirect
from django.template import RequestContext,loader
from django.template.loader import render_to_string
from .models import AppUser
from .forms import SignInForm,PasswordResetForm,ForgotPasswordForm,PasswordSetForm
from .utils import get_user_model

import datetime, random, sha

from django.db.models import Sum

from django.utils import translation
from django.utils.translation import check_for_language




def send_welcome_mail(user):
    subject = _('Activate your account')
                
    html_content = render_to_string('registration/mail/welcome.html', { 'site_url': settings.SITE_URL, 
                                            'verification_key': user.verification_key,
                                            'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS })
    text_content = strip_tags(html_content)
                
    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_TO, to=[user.email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()
    return True

@login_required(login_url='/signin')
def resend_verification(request):

    email = request.user.email
    salt = sha.new(str(random.random())).hexdigest()[:5]
    verification_key = sha.new(salt+email).hexdigest()
    subject = _('Activate your new account')
    html_content = render_to_string('registration/mail/welcome.html', { 'site_url': settings.SITE_URL, 
                                        'verification_key': verification_key,
                                        'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS })
    text_content = strip_tags(html_content)
    msg = EmailMultiAlternatives(subject, text_content, settings.EMAIL_TO, to=[email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()       
    member = request.user
    member.verification_key = verification_key
    member.save()
    return HttpResponseRedirect(reverse(settings.USER_PROFILE_VIEW))


def verify(request, verification_key):
    verification_key = verification_key.lower()
    account = AppUser.objects.verify_user(verification_key)
    form = PasswordSetForm()
    if request.method == 'POST':
        form = PasswordSetForm(request.POST)
        if form.is_valid():
            password=request.POST.get('password1')
            account.set_password(password)
            account.save()
            user = authenticate(username=account.email, password=password)
            if user is not None:
                login(request,user)
                return HttpResponseRedirect('/')
                   
    title = _('Set your password')
    variables = RequestContext(request, {'title':title,'account': account,'form': form,'root':settings.STATIC_ROOT})
    return render_to_response('registration/set_password.html',variables)

def signout(request):
    logout(request)
    return HttpResponseRedirect('/signin/')

def signin(request):
    """Login handler.
    """
    if request.user.is_authenticated():
        DEFAULT_URL = reverse('home')
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', DEFAULT_URL))  
    if request.method == 'GET':
        form = SignInForm()
    else:
        form = SignInForm(request.POST)
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    if 'next' in request.GET:
                        return HttpResponseRedirect(request.GET['next'])
                    DEFAULT_URL = reverse('home')
                    return HttpResponseRedirect(request.META.get('HTTP_REFERER', DEFAULT_URL))  
                        
                else:
                    messages.add_message(request, messages.ERROR, "Account disabled.")
            else:
                messages.add_message(request, messages.ERROR, "Login failed.")
    title = 'Login'
    variables = RequestContext(request, {'title':title,'form':form})
        
    return render_to_response('registration/signin.html',variables)


class SaltMixin(object):
    salt = 'password_recovery'
    url_salt = 'password_recovery_url'


def loads_with_timestamp(value, salt):
    """Returns the unsigned value along with its timestamp, the time when it
    got dumped."""
    try:
        signing.loads(value, salt=salt, max_age=-1)
    except signing.SignatureExpired as e:
        age = float(str(e).split('Signature age ')[1].split(' >')[0])
        timestamp = timezone.now() - datetime.timedelta(seconds=age)
        return timestamp, signing.loads(value, salt=salt)


class RecoverDone(SaltMixin, generic.TemplateView):
    template_name = "registration/reset_sent.html"

    def get_context_data(self, **kwargs):
        ctx = super(RecoverDone, self).get_context_data(**kwargs)
        try:
            ctx['timestamp'], ctx['email'] = loads_with_timestamp(
                self.kwargs['signature'], salt=self.url_salt,
            )
        except signing.BadSignature:
            raise Http404
        return ctx
recover_done = RecoverDone.as_view()


class Recover(SaltMixin, generic.FormView):
    case_sensitive = True
    form_class = ForgotPasswordForm
    template_name = 'registration/recovery_form.html'
    email_template_name = 'registration/mail/recovery_email.txt'
    email_subject_template_name = 'registration/mail/recovery_email_subject.txt'
    
    def get_success_url(self):
        return reverse('password_reset_sent', args=[self.mail_signature])

    def get_context_data(self, **kwargs):
        kwargs['url'] = self.request.get_full_path()
        return super(Recover, self).get_context_data(**kwargs)

    def get_form_kwargs(self):
        kwargs = super(Recover, self).get_form_kwargs()
       
        return kwargs

    def send_notification(self):
        context = {
            'site': RequestSite(self.request),
            'user': self.user,
            'token': signing.dumps(self.user.pk, salt=self.salt),
            'secure': self.request.is_secure(),
        }
        body = loader.render_to_string(self.email_template_name,
                                       context).strip()
        subject = loader.render_to_string(self.email_subject_template_name,
                                          context).strip()
        send_mail(subject, body, settings.EMAIL_TO,
                  [self.user.email])

    def form_valid(self, form):
        self.user = form.cleaned_data['email']
        self.send_notification()
        email = self.user.email
        self.mail_signature = signing.dumps(email, salt=self.url_salt)
        return super(Recover, self).form_valid(form)
recover = Recover.as_view()


class Reset(SaltMixin, generic.FormView):
    form_class = PasswordResetForm
    token_expires = 3600 * 48
    template_name = 'registration/reset.html'
    success_url = reverse_lazy('password_reset_done')

    def dispatch(self, request, *args, **kwargs):
        self.request = request
        self.args = args
        self.kwargs = kwargs

        try:
            pk = signing.loads(kwargs['token'], max_age=self.token_expires,
                               salt=self.salt)
        except signing.BadSignature:
            return self.invalid()

        self.user = get_object_or_404(get_user_model(), pk=pk)
        return super(Reset, self).dispatch(request, *args, **kwargs)

    def invalid(self):
        return self.render_to_response(self.get_context_data(invalid=True))

    def get_form_kwargs(self):
        kwargs = super(Reset, self).get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super(Reset, self).get_context_data(**kwargs)
        if 'invalid' not in ctx:
            ctx.update({
                'username': self.user.email,
                'token': self.kwargs['token'],
            })
        return ctx

    def form_valid(self, form):
        form.save()
        return redirect(self.get_success_url())
reset = Reset.as_view()


class ResetDone(generic.TemplateView):
    template_name = 'registration/recovery_done.html'


reset_done = ResetDone.as_view()

class Home(generic.TemplateView):
    template_name = 'registration/index.html'


home = Home.as_view()