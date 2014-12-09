from django import forms
from .models import AppUser
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate
from django.forms import ModelForm

class SignInForm(forms.Form):
    """Login form.
    """
    username = forms.CharField(max_length=100, required=True,widget=forms.TextInput(attrs={'class':'form-control no-border input-lg rounded', 'placeholder':_("Enter Email"),'autofocus':'True'}),
                                label=u'')
    password = forms.CharField(widget=forms.widgets.PasswordInput(attrs={'class':'form-control no-border input-lg rounded', 'placeholder':_("Enter password")}), required=True)
    def clean_username(self):
        """
        Validates that the email is not already in use.
        
        """
        if self.cleaned_data.get('username', None):
            try:
                user = AppUser.objects.get(email__exact=self.cleaned_data['username'])
            except AppUser.DoesNotExist:
                raise forms.ValidationError(_('username does not exists.'))
            return self.cleaned_data['username']
    def clean_password(self):
        """
        Validates that the email is not already in use.
        
        """
        if self.cleaned_data.get('password', None):
            try:
                user = authenticate(username=self.cleaned_data['username'], password=self.cleaned_data['password'])
                print user.id
            except:
                raise forms.ValidationError(_('username and password does not match.') )

            return self.cleaned_data['password']

class PasswordSetForm(forms.Form):
    password1 = forms.CharField(
        label=_('New password'),
        widget=forms.PasswordInput(attrs={'class':'form-control no-border input-lg rounded', 'placeholder':_("New Password")}),
    )
    password2 = forms.CharField(
        label=_('New password (confirm)'),
        widget=forms.PasswordInput(attrs={'class':'form-control no-border input-lg rounded', 'placeholder':_("New Password(confirm)")}),
    )

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1', '')
        password2 = self.cleaned_data['password2']
        if not password1 == password2:
            raise forms.ValidationError(_("The two passwords didn't match."))
        return password2

    

class PasswordResetForm(forms.Form):
    password1 = forms.CharField(
        label=_('New password'),
        widget=forms.PasswordInput(attrs={'class':'form-control logpadding', 'placeholder':_("New Password")}),
    )
    password2 = forms.CharField(
        label=_('New password (confirm)'),
        widget=forms.PasswordInput(attrs={'class':'form-control logpadding', 'placeholder':_("New Password(confirm)")}),
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super(PasswordResetForm, self).__init__(*args, **kwargs)

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1', '')
        password2 = self.cleaned_data['password2']
        if not password1 == password2:
            raise forms.ValidationError(_("The two passwords didn't match."))
        return password2

    def save(self):
        self.user.set_password(self.cleaned_data['password1'])
        AppUser.objects.filter(pk=self.user.pk).update(
            password=self.user.password,
        )

class ForgotPasswordForm(forms.Form):
    """Login form.
    """
    email = forms.EmailField(widget=forms.TextInput(attrs={'id':'inputRegisterEmail','class':'form-control no-border input-lg rounded'}),
                                label=u'')
    def clean_email(self):
        """
        Validates that the email is not already in use.
        
        """
        if self.cleaned_data.get('email', None):
            try:
                user = AppUser.objects.get(email__exact=self.cleaned_data['email'])
                return user
            except AppUser.DoesNotExist:
                raise forms.ValidationError(u'Email "%s" does not exists.' % self.cleaned_data['email'])
            return self.cleaned_data['email']

