from django.db import models
from django.contrib.auth.models import User
from django.dispatch import receiver
import os


class Activation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    code = models.CharField(max_length=20, unique=True)
    email = models.EmailField(blank=True)





class UploadedDocuments(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    documents = models.FileField(upload_to='documents', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "uploaded_documents"


@receiver(models.signals.post_delete, sender=UploadedDocuments)
def auto_delete_file_on_delete1(sender, instance, **kwargs):
    """
    Deletes file from filesystem
    when corresponding `MediaFile` object is deleted.
    """
    print('inside deleting media file')
    if instance.documents:
        if os.path.isfile(instance.documents.path):
            os.remove(instance.documents.path)


@receiver(models.signals.pre_save, sender=UploadedDocuments)
def auto_delete_file_on_change1(sender, instance, **kwargs):
    """
    Deletes old file from filesystem
    when corresponding `MediaFile` object is updated
    with new file.
    """
    if not instance.pk:
        return False
    print(instance.pk)
    try:
        old_file = UploadedDocuments.objects.get(pk=instance.pk).documents

    except UploadedDocuments.DoesNotExist:
        return False

    new_file = instance.documents
    if not old_file == new_file:
        if os.path.isfile(old_file.path):
            os.remove(old_file.path)


class UploadedDocumentsStegno(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    documents = models.FileField(upload_to='documents', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "uploaded_documents_stegno"


@receiver(models.signals.post_delete, sender=UploadedDocumentsStegno)
def auto_delete_file_on_delete(sender, instance, **kwargs):
    """
    Deletes file from filesystem
    when corresponding `MediaFile` object is deleted.
    """
    print('inside deleting media file stegno')
    if instance.documents:
        if os.path.isfile(instance.documents.path):
            os.remove(instance.documents.path)


@receiver(models.signals.pre_save, sender=UploadedDocumentsStegno)
def auto_delete_file_on_change(sender, instance, **kwargs):
    """
    Deletes old file from filesystem
    when corresponding `MediaFile` object is updated
    with new file.
    """
    if not instance.pk:
        return False

    try:
        old_file = UploadedDocumentsStegno.objects.get(pk=instance.pk).documents
    except UploadedDocumentsStegno.DoesNotExist:
        return False

    new_file = instance.documents
    if not old_file == new_file:
        if os.path.isfile(old_file.path):
            os.remove(old_file.path)


class ShareFile(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE,related_name='sender')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE,related_name='receiver')
    file_id = models.ForeignKey(UploadedDocuments, on_delete=models.CASCADE)
    shared_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "shared_files"
        unique_together = ('sender', 'receiver','file_id')

class ShareFileStegnoModel(models.Model):
    sender_stengo = models.ForeignKey(User, on_delete=models.CASCADE,related_name='sender_stengo')
    receiver_stegno = models.ForeignKey(User, on_delete=models.CASCADE,related_name='receiver_stegno')
    file_id = models.ForeignKey(UploadedDocumentsStegno, on_delete=models.CASCADE)
    shared_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "shared_files_stegno"
        unique_together = ('sender_stengo', 'receiver_stegno','file_id')