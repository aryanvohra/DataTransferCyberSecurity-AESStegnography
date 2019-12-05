# Generated by Django 2.1.1 on 2018-09-24 13:15

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('accounts', '0004_auto_20180924_0550'),
    ]

    operations = [
        migrations.CreateModel(
            name='ShareFileStegnoModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('shared_at', models.DateTimeField(auto_now_add=True)),
                ('file_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='accounts.UploadedDocuments')),
                ('receiver_stegno', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='receiver_stegno', to=settings.AUTH_USER_MODEL)),
                ('sender_stengo', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sender_stengo', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'shared_files_stegno',
            },
        ),
        migrations.AlterUniqueTogether(
            name='sharefilestegnomodel',
            unique_together={('sender_stengo', 'receiver_stegno', 'file_id')},
        ),
    ]