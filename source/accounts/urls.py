from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import (
    LogInView, ResendActivationCodeView, RemindUsernameView, SignUpView, ActivateView, LogOutView,
    ChangeEmailView, ChangeEmailActivateView, ChangeProfileView, ChangePasswordView,
    RestorePasswordView, RestorePasswordDoneView,
    RestorePasswordConfirmView, SaveProfile, DetailView, DecryptFile, HideFile, DetailStegnoView,
    UnhideFile, DeleteTempStegno, DeleteFileStegnoView, DeleteFileCryptoView,
    StegnoUserListView, CryptoUserListView, ShareFileCryptoView,ShareFileStegnoView,DeleteShareStegnoView,DeleteShareCryptoView,DeleteTempCrypto
)
from . import views
app_name = 'accounts'
from django.views.generic import TemplateView
urlpatterns = [
    path('log-in/', LogInView.as_view(), name='log_in'),
    path('log-out/', LogOutView.as_view(), name='log_out'),

    path('resend/activation-code/', ResendActivationCodeView.as_view(), name='resend_activation_code'),

    path('sign-up/', SignUpView.as_view(), name='sign_up'),
    path('activate/<code>/', ActivateView.as_view(), name='activate'),

    path('restore/password/', RestorePasswordView.as_view(), name='restore_password'),
    path('restore/password/done/', RestorePasswordDoneView.as_view(), name='restore_password_done'),
    path('restore/<uidb64>/<token>/', RestorePasswordConfirmView.as_view(), name='restore_password_confirm'),

    path('remind/username/', RemindUsernameView.as_view(), name='remind_username'),

    path('change/profile/', ChangeProfileView.as_view(), name='change_profile'),
    path('change/password/', ChangePasswordView.as_view(), name='change_password'),
    path('change/email/', ChangeEmailView.as_view(), name='change_email'),
    path('change/email/<code>/', ChangeEmailActivateView.as_view(), name='change_email_activation'),
    path('profile/', TemplateView.as_view(template_name='upload_file.html'), name='profile'),
    path('stegno/', TemplateView.as_view(template_name='upload_file_stegno.html'), name='stegno'),
    path('saved/', SaveProfile, name='saved'),
    path('hideFile/', HideFile, name='hideFile'),
    path('decrypt/', DecryptFile, name='decrypt'),
    path('dstegno/', UnhideFile, name='dstegno'),
    path('delete_stegno_temp/', DeleteTempStegno, name='delete_stegno_temp'),
    path('delete_crypto_temp/', DeleteTempCrypto, name='delete_crypto_temp'),

    path('uploaded/crypto/',views.FilesListView.as_view(), name='uploaded_files'),
    path('uploaded/stegno/',views.FilesStegnoListView.as_view(), name='uploaded_files_stegno'),
    path('details/<int:pk>', DetailView.as_view(), name='details'),
    path('details_stegno/<int:pk>', DetailStegnoView.as_view(), name='details_stegno'),
    path('delete_stegno/<int:pk>', DeleteFileStegnoView.as_view(), name='delete_stegno'),
    path('delete_crypto/<int:pk>', DeleteFileCryptoView.as_view(), name='delete_crypto'),
    path('get_users', CryptoUserListView, name='get_users'),
    path('get_users_stegno', StegnoUserListView, name='get_users_stegno'),
    path('share_crypto_file', ShareFileCryptoView, name='share_crypto_file'),
    path('share_stegno_file', ShareFileStegnoView, name='share_stegno_file'),
    path('shared_files/stegno', views.FilesSharedListView.as_view(), name='shared_files_stegno'),
    path('shared_files/crypto', views.FilesSharedCryptoListView.as_view(), name='shared_files_crypto'),
    path('delete_share/stegno/<int:pk>', DeleteShareStegnoView.as_view(), name='delete_share_stegno'),
    path('delete_share/crypto/<int:pk>', DeleteShareCryptoView.as_view(), name='delete_share_crypto'),






]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
