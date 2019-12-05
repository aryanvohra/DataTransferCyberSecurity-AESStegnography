from __future__ import absolute_import, unicode_literals
from django.contrib import messages
from django.contrib.auth import login, authenticate, REDIRECT_FIELD_NAME
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    LogoutView as BaseLogoutView, PasswordChangeView as BasePasswordChangeView,
    PasswordResetDoneView as BasePasswordResetDoneView, PasswordResetConfirmView as BasePasswordResetConfirmView,
)
from django.shortcuts import get_object_or_404, redirect
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.http import is_safe_url
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View, FormView
from django.conf import settings

from .utils import (
    send_activation_email, send_reset_password_email, send_forgotten_username_email, send_activation_change_email,
)
from .forms import (
    SignInViaUsernameForm, SignInViaEmailForm, SignInViaEmailOrUsernameForm, SignUpForm,
    RestorePasswordForm, RestorePasswordViaEmailOrUsernameForm, RemindUsernameForm,
    ResendActivationCodeForm, ResendActivationCodeViaEmailForm, ChangeProfileForm, ChangeEmailForm,
)
from .models import Activation


class GuestOnlyView(View):
    def dispatch(self, request, *args, **kwargs):
        # Redirect to the index page if the user already authenticated
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)

        return super().dispatch(request, *args, **kwargs)


class LogInView(GuestOnlyView, FormView):
    template_name = 'accounts/log_in.html'

    @staticmethod
    def get_form_class(**kwargs):
        if settings.DISABLE_USERNAME or settings.LOGIN_VIA_EMAIL:
            return SignInViaEmailForm

        if settings.LOGIN_VIA_EMAIL_OR_USERNAME:
            return SignInViaEmailOrUsernameForm

        return SignInViaUsernameForm

    @method_decorator(sensitive_post_parameters('password'))
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # Sets a test cookie to make sure the user has cookies enabled
        request.session.set_test_cookie()

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        request = self.request

        # If the test cookie worked, go ahead and delete it since its no longer needed
        if request.session.test_cookie_worked():
            request.session.delete_test_cookie()

        # The default Django's "remember me" lifetime is 2 weeks and can be changed by modifying
        # the SESSION_COOKIE_AGE settings' option.
        if settings.USE_REMEMBER_ME:
            if not form.cleaned_data['remember_me']:
                request.session.set_expiry(0)

        login(request, form.user_cache)

        redirect_to = request.POST.get(REDIRECT_FIELD_NAME, request.GET.get(REDIRECT_FIELD_NAME))
        url_is_safe = is_safe_url(redirect_to, allowed_hosts=request.get_host(), require_https=request.is_secure())

        if url_is_safe:
            return redirect(redirect_to)

        return redirect(settings.LOGIN_REDIRECT_URL)


class SignUpView(GuestOnlyView, FormView):
    template_name = 'accounts/sign_up.html'
    form_class = SignUpForm

    def form_valid(self, form):
        request = self.request
        user = form.save(commit=False)

        if settings.DISABLE_USERNAME:
            # Set a temporary username
            user.username = get_random_string()
        else:
            user.username = form.cleaned_data['username']

        if settings.ENABLE_USER_ACTIVATION:
            user.is_active = False

        # Create a user record
        user.save()

        # Change the username to the "user_ID" form
        if settings.DISABLE_USERNAME:
            user.username = f'user_{user.id}'
            user.save()

        if settings.ENABLE_USER_ACTIVATION:
            code = get_random_string(20)

            act = Activation()
            act.code = code
            act.user = user
            act.save()

            send_activation_email(request, user.email, code)

            messages.success(
                request, _('You are signed up. To activate the account, follow the link sent to the mail.'))
        else:
            raw_password = form.cleaned_data['password1']

            user = authenticate(username=user.username, password=raw_password)
            login(request, user)

            messages.success(request, _('You are successfully signed up!'))

        return redirect('index')


class ActivateView(View):
    @staticmethod
    def get(request, code):
        act = get_object_or_404(Activation, code=code)

        # Activate profile
        user = act.user
        user.is_active = True
        user.save()

        # Remove the activation record
        act.delete()

        messages.success(request, _('You have successfully activated your account!'))

        return redirect('accounts:log_in')


class ResendActivationCodeView(GuestOnlyView, FormView):
    template_name = 'accounts/resend_activation_code.html'

    @staticmethod
    def get_form_class(**kwargs):
        if settings.DISABLE_USERNAME:
            return ResendActivationCodeViaEmailForm

        return ResendActivationCodeForm

    def form_valid(self, form):
        user = form.user_cache

        activation = user.activation_set.first()
        activation.delete()

        code = get_random_string(20)

        act = Activation()
        act.code = code
        act.user = user
        act.save()

        send_activation_email(self.request, user.email, code)

        messages.success(self.request, _('A new activation code has been sent to your email address.'))

        return redirect('accounts:resend_activation_code')


class RestorePasswordView(GuestOnlyView, FormView):
    template_name = 'accounts/restore_password.html'

    @staticmethod
    def get_form_class(**kwargs):
        if settings.RESTORE_PASSWORD_VIA_EMAIL_OR_USERNAME:
            return RestorePasswordViaEmailOrUsernameForm

        return RestorePasswordForm

    def form_valid(self, form):
        user = form.user_cache
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk)).decode()

        send_reset_password_email(self.request, user.email, token, uid)

        return redirect('accounts:restore_password_done')


class ChangeProfileView(LoginRequiredMixin, FormView):
    template_name = 'accounts/profile/change_profile.html'
    form_class = ChangeProfileForm

    def get_initial(self):
        user = self.request.user
        initial = super().get_initial()
        initial['first_name'] = user.first_name
        initial['last_name'] = user.last_name
        return initial

    def form_valid(self, form):
        user = self.request.user
        user.first_name = form.cleaned_data['first_name']
        user.last_name = form.cleaned_data['last_name']
        user.save()

        messages.success(self.request, _('Profile data has been successfully updated.'))

        return redirect('accounts:change_profile')


class ChangeEmailView(LoginRequiredMixin, FormView):
    template_name = 'accounts/profile/change_email.html'
    form_class = ChangeEmailForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def get_initial(self):
        initial = super().get_initial()
        initial['email'] = self.request.user.email
        return initial

    def form_valid(self, form):
        user = self.request.user
        email = form.cleaned_data['email']

        if settings.ENABLE_ACTIVATION_AFTER_EMAIL_CHANGE:
            code = get_random_string(20)

            act = Activation()
            act.code = code
            act.user = user
            act.email = email
            act.save()

            send_activation_change_email(self.request, email, code)

            messages.success(self.request, _('To complete the change of email address, click on the link sent to it.'))
        else:
            user.email = email
            user.save()

            messages.success(self.request, _('Email successfully changed.'))

        return redirect('accounts:change_email')


class ChangeEmailActivateView(View):
    @staticmethod
    def get(request, code):
        act = get_object_or_404(Activation, code=code)

        # Change the email
        user = act.user
        user.email = act.email
        user.save()

        # Remove the activation record
        act.delete()

        messages.success(request, _('You have successfully changed your email!'))

        return redirect('accounts:change_email')


class RemindUsernameView(GuestOnlyView, FormView):
    template_name = 'accounts/remind_username.html'
    form_class = RemindUsernameForm

    def form_valid(self, form):
        user = form.user_cache
        send_forgotten_username_email(user.email, user.username)

        messages.success(self.request, _('Your username has been successfully sent to your email.'))

        return redirect('accounts:remind_username')


class ChangePasswordView(BasePasswordChangeView):
    template_name = 'accounts/profile/change_password.html'

    def form_valid(self, form):
        # Change the password
        user = form.save()

        # Re-authentication
        login(self.request, user)

        messages.success(self.request, _('Your password was changed.'))

        return redirect('accounts:change_password')


class RestorePasswordConfirmView(BasePasswordResetConfirmView):
    template_name = 'accounts/restore_password_confirm.html'

    def form_valid(self, form):
        # Change the password
        form.save()

        messages.success(self.request, _('Your password has been set. You may go ahead and log in now.'))

        return redirect('accounts:log_in')


class RestorePasswordDoneView(BasePasswordResetDoneView):
    template_name = 'accounts/restore_password_done.html'


class LogOutView(LoginRequiredMixin, BaseLogoutView):
    template_name = 'accounts/log_out.html'


from .forms import DocumentForm
from .models import UploadedDocuments
from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from datetime import datetime
import os

from datetime import date
def SaveProfile(request):
    saved = False

    if request.method == "POST" and request.FILES['documents']:

        # to save in db
        myfile = request.FILES['documents']

        fs = FileSystemStorage()
        extension = os.path.splitext(myfile.name)[1]
        print(extension)
        new_file_name = datetime.now().strftime('%Y_%m_%d_%h_%M_%S%f')+extension
        filename = fs.save(new_file_name, myfile)
        uploaded_file_url = fs.url(filename)
        password = request.POST.get('password', '')
        print(password)
        path1 = fs.path(filename)

        # path1=fs.path(filename)+'.enc'
        print(path1)
        # iv1=os.urandom(16)


        encrypt_file(password, path1)
        os.remove(fs.path(filename))
        print(new_file_name)

        # decrypt_file('1234567891234567',path1)
        form = DocumentForm(request.POST or None, request.FILES)

        if form.is_valid():
            document = form.save(commit=False)
            document.documents = new_file_name + '.enc'
            document.user = request.user
            document.save()
            path = 'documents/' + filename
            print(path)
            if os.path.isfile(path):
                os.remove(path)
            saved = True
        print(form.errors)
    if saved:
        messages.success(request, _('File Uploaded Successfully'))
    else:
        messages.success(request, _('Failed to upload File'))

    return render(request, 'upload_file.html', locals())


from .LsbFileSteg import encodeLSB, decodeLSB

from .forms import DocumentFormStegno


def HideFile(request):
    saved = False

    if request.method == "POST" and request.FILES['cover_file']:

        # to save in db
        cover_file = request.FILES['cover_file']
        data_file = request.FILES['data_file']
        fs = FileSystemStorage()

        # extension = os.path.splitext(data_file.name)[1]
        # print(extension)
        # data_file.name = datetime.now().strftime('%Y_%m_%d_%h_%M_%S%f') + extension
        cover_file_filename = fs.save(cover_file.name, cover_file)
        data_file_filename = fs.save(data_file.name, data_file)

        print(cover_file_filename)
        print(data_file_filename)
        cover_file_path = fs.path(cover_file_filename)
        data_file_path = fs.path(data_file_filename)
        print(cover_file_path)
        print(data_file_path)
        final_path = cover_file_path + 'hello'
        img = encodeLSB(data_file_path, cover_file_path, final_path)
        if os.path.isfile(cover_file_path):
            os.remove(cover_file_path)
        if os.path.isfile(data_file_path):
            os.remove(data_file_path)
        print('here')
        os.rename(final_path + '.png', cover_file_path)
        print('here1')

        form = DocumentFormStegno(request.POST or None)
        document = form.save(commit=False)
        document.documents = cover_file_filename
        document.user = request.user
        document.save()
        print("Encoding finished.")
        saved = True
    if saved:
        messages.success(request, _('File Uploaded Successfully'))
    else:
        messages.success(request, _('Failed to upload File'))

    return render(request, 'upload_file_stegno.html', locals())


from PIL import Image


def DecryptFile(request):
    saved = False

    if request.method == "POST":
        password = request.POST.get('password', '')
        documents = request.POST.get('documents', '')
        print('pass' + password)
        print('docu' + documents)
        fs = FileSystemStorage()
        print('fleurl1' + fs.path(documents))

        path1 = fs.path(documents)

        print('path' + path1)
        # iv1=os.urandom(16)
        output_file = decrypt_file(password, path1)
        file2 = documents.replace(".enc", "")
        print(file2)
        uploaded_file_url = fs.url(file2)
        print(uploaded_file_url)
        saved = True
    if saved:
        messages.success(request, _('File Decrypted Successfully'))
        return render(request, 'accounts/download_crypto.html', {
            'uploaded_file_url': uploaded_file_url
        })
    else:
        messages.success(request, _('Failed to Decrypt File'))
        return render(request, 'core/upload_file.html')


def UnhideFile(request):
    saved = False

    if request.method == "POST":
        documents = request.POST.get('documents', '')

        print('docu' + documents)
        fs = FileSystemStorage()
        print('fleurl1' + fs.path(documents))

        path1 = fs.path(documents)

        print('path' + path1)
        finalfile = path1 + 'temp'
        print('before' + finalfile)
        decodeLSB(path1, finalfile)
        finalfile = documents + 'temp.txt'
        print('after' + finalfile)
        uploaded_file_url = fs.url(finalfile)
        print(uploaded_file_url)
        saved = True
    if saved:
        messages.success(request, _('File Unhidden Successfully'))
        return render(request, 'accounts/download.html', {
            'uploaded_file_url': uploaded_file_url
        })
    else:
        messages.success(request, _('Failed to Decrypt File'))
        return render(request, 'accounts/show_details_stegno.html')


def DeleteTempStegno(request):
    saved = False
    print('before')
    if request.method == "POST":
        print('here')
        documents = request.POST.get('documents', '')
        documents = documents.replace('media/', '')
        documents = documents.replace('/', '')

        print('docu' + documents)
        fs = FileSystemStorage()
        print('fleurl1' + fs.path(documents))

        path1 = fs.path(documents)
        os.remove(path1)

        saved = True
    if saved:
        messages.success(request, _('File removed Successfully'))
        return redirect('accounts:uploaded_files_stegno')
    else:
        messages.success(request, _('Failed to remove File'))
        return redirect('accounts:uploaded_files_stegno')
def DeleteTempCrypto(request):
    saved = False
    print('before')
    if request.method == "POST":
        print('here')
        documents = request.POST.get('documents', '')
        documents = documents.replace('media/', '')
        documents = documents.replace('/', '')

        print('docu' + documents)
        fs = FileSystemStorage()
        print('fleurl1' + fs.path(documents))

        path1 = fs.path(documents)
        os.remove(path1)

        saved = True
    if saved:
        messages.success(request, _('File removed Successfully'))
        return redirect('accounts:uploaded_files')
    else:
        messages.success(request, _('Failed to remove File'))
        return redirect('accounts:uploaded_files')

def DeleteFileStegno(request):
    saved = False
    print('before')
    if request.method == "POST":
        print('here')
        form = DocumentFormStegno(request.POST or None)
        form.delete()
        saved = True
    if saved:
        messages.success(request, _('File removed Successfully'))
        return redirect('accounts:uploaded_files_stegno')
    else:
        messages.success(request, _('Failed to remove File'))
        return redirect('accounts:uploaded_files_stegno')


import os, random, struct
from Crypto.Cipher import AES


def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    # iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    iv = os.urandom(16)
    print(iv)
    print(in_filename)
    # encryptor = AES.new(key, AES.MODE_CBC, iv)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += (' ' * (16 - len(chunk) % 16)).encode('ascii')

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    print(out_filename)
    print(in_filename)
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
    return out_filename


from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.http import Http404

from django.views import generic
from .models import UploadedDocuments, UploadedDocumentsStegno
from django.contrib.auth.models import User


class FilesListView(LoginRequiredMixin, generic.ListView):
    paginate_by = 10

    def get_queryset(self):
        current_user = self.request.user
        model = UploadedDocuments.objects.order_by('-id').filter(user=current_user.id)

        return model


class FilesStegnoListView(LoginRequiredMixin, generic.ListView):
    paginate_by = 10

    def get_queryset(self):
        current_user = self.request.user
        model = UploadedDocumentsStegno.objects.order_by('-id').filter(user=current_user.id)
        return model


class DetailView(generic.DetailView):
    model = UploadedDocuments
    template_name = 'accounts/show_details.html'


class DetailStegnoView(generic.DetailView):
    model = UploadedDocumentsStegno
    template_name = 'accounts/show_details_stegno.html'


from django.urls import reverse_lazy
from django.views.generic.edit import DeleteView


class DeleteFileStegnoView(DeleteView):
    model = UploadedDocumentsStegno
    template_name = 'accounts/stegno_confirm_delete.html'
    success_url = reverse_lazy('accounts:uploaded_files_stegno')


class DeleteFileCryptoView(DeleteView):
    model = UploadedDocuments
    template_name = 'accounts/crypto_confirm_delete.html'
    success_url = reverse_lazy('accounts:uploaded_files')


from django.db.models import Q


class PersonListView(LoginRequiredMixin, generic.ListView):
    template_name = 'accounts/user_list.html'

    def get_queryset(self):
        current_user = self.request.user
        model = User.objects.order_by('-first_name').filter(~Q(id=current_user.id))
        print(model)
        return model


def CryptoUserListView(request):
    current_user = request.user
    fileid = request.GET['fileid']
    object_list = User.objects.order_by('-first_name').filter(~Q(id=current_user.id))
    print(object_list)
    print(fileid)
    return render(request, 'accounts/user_list.html', {
        'object_list': object_list, 'current_user': current_user, 'fileid': fileid
    })

def StegnoUserListView(request):
    current_user = request.user
    fileid = request.GET['fileid']
    object_list = User.objects.order_by('-first_name').filter(~Q(id=current_user.id))
    print(object_list)
    print(fileid)
    return render(request, 'accounts/user_list_stegno.html', {
        'object_list': object_list, 'current_user': current_user, 'fileid': fileid
    })

from .forms import ShareFileCryptoForm


def ShareFileCryptoView(request):
    saved = False

    if request.method == "POST":
        try:
            form = ShareFileCryptoForm(request.POST or None)
            form1 = form.instance

            receiver = request.POST.get('receiver', '')
            print('receiver', receiver)
            fileid = request.POST.get('file_id', '')
            print('receiver', fileid)
            form1.sender = request.user
            form1.receiver = User.objects.get_by_natural_key(receiver)
            files = UploadedDocuments.objects.filter(id=fileid)
            for doc in files:
                fileid = doc


            form1.file_id =fileid
            # book = Book.objects.get(script_title="some_title")
            print('entries done')

            if form.is_valid():
                form1.save()
                saved = True
            print(form.errors)
            if saved:
                messages.success(request, _('File Shared Successfully'))
            else:
                messages.success(request, _('Failed to Share File'))
        except Exception as e:
            print(e)
            messages.success(request,('File already shared'))

    return redirect('accounts:uploaded_files')
from .forms import ShareFileStegnoForm

def ShareFileStegnoView(request):
    saved = False

    if request.method == "POST":
        try:
            form = ShareFileStegnoForm(request.POST or None)
            form1 = form.instance

            receiver = request.POST.get('receiver', '')
            print('receiver', receiver)
            fileid = request.POST.get('file_id', '')
            print('fileid', fileid)
            form1.sender_stengo_id = request.user.id
            form1.receiver_stegno_id = User.objects.get_by_natural_key(receiver).id
            files = UploadedDocumentsStegno.objects.filter(id=fileid)
            for doc in files:
                fileid = doc
            form1.file_id_id =fileid.id
            # book = Book.objects.get(script_title="some_title")
            print('entries done')

            if form.is_valid():
                form1.save()
                saved = True
            print(form.errors)
            if saved:
                messages.success(request, _('File Shared Successfully'))
            else:
                messages.success(request, _('Failed to Share File'))
        except Exception as e:
            print('exception==')
            print(e)
            print('exception finished')
            messages.success(request,('File already shared'))

    return redirect('accounts:uploaded_files_stegno')

from .models import ShareFileStegnoModel
from operator import __or__ as OR
from functools import reduce
class FilesSharedListView(LoginRequiredMixin, generic.ListView):
    paginate_by = 10

    def get_queryset(self):
        current_user = self.request.user
        lst = [Q(sender_stengo=current_user.id), Q(receiver_stegno=current_user.id)]
        model = ShareFileStegnoModel.objects.order_by('-id').filter(reduce(OR, lst))
        return model

from .models import ShareFile

class FilesSharedCryptoListView(LoginRequiredMixin, generic.ListView):
    paginate_by = 10

    def get_queryset(self):
        current_user = self.request.user
        lst = [Q(sender=current_user.id), Q(receiver=current_user.id)]
        model = ShareFile.objects.order_by('-id').filter(reduce(OR,lst))
        return model

class DeleteShareStegnoView(DeleteView):
    model = ShareFileStegnoModel

    success_url = reverse_lazy('accounts:shared_files_stegno')

class DeleteShareCryptoView(DeleteView):
    model = ShareFile

    success_url = reverse_lazy('accounts:shared_files_crypto')