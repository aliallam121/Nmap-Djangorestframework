# Generated by Django 4.0.6 on 2022-07-16 23:57

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Host',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.GenericIPAddressField()),
                ('mac_address', models.CharField(max_length=20, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
            ],
            options={
                'ordering': ['-created_on'],
            },
        ),
        migrations.CreateModel(
            name='OperativeSystemMatch',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('accuracy', models.PositiveSmallIntegerField()),
                ('line', models.PositiveSmallIntegerField()),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='has_possible_os_match', to='Nmap.host')),
            ],
            options={
                'ordering': ['-created_on'],
            },
        ),
        migrations.CreateModel(
            name='Port',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('protocol', models.CharField(max_length=255)),
                ('port_number', models.PositiveSmallIntegerField()),
                ('state', models.CharField(max_length=255)),
                ('reason', models.CharField(max_length=255)),
                ('reason_ttl', models.PositiveSmallIntegerField()),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='host_ports', to='Nmap.host')),
            ],
            options={
                'ordering': ['-port_number'],
                'unique_together': {('protocol', 'port_number', 'host', 'state', 'reason_ttl')},
            },
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('priority', models.PositiveSmallIntegerField()),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='create_project', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-priority'],
            },
        ),
        migrations.CreateModel(
            name='Range',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain_name', models.CharField(blank=True, default='unkown', max_length=255, null=True)),
                ('ip_range', models.GenericIPAddressField(verbose_name='target address')),
                ('mask', models.IntegerField(default=32, verbose_name='Mask')),
                ('given', models.CharField(blank=True, default='ip', max_length=255, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='has_ranges', to='Nmap.project')),
            ],
            options={
                'ordering': ['-created_on'],
            },
        ),
        migrations.CreateModel(
            name='OperativeSystemClass',
            fields=[
                ('operative_system_match', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='specs', serialize=False, to='Nmap.operativesystemmatch')),
                ('type', models.CharField(max_length=255)),
                ('vendor', models.CharField(max_length=255)),
                ('operative_system_family', models.CharField(max_length=255)),
                ('operative_system_generation', models.CharField(max_length=255)),
                ('accuracy', models.PositiveSmallIntegerField()),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
            ],
        ),
        migrations.CreateModel(
            name='ScannerHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scanname', models.CharField(max_length=255, unique=True)),
                ('status', models.CharField(choices=[('PENDING', 'PENDING'), ('FINISHED', 'FINISHED'), ('FAILED', 'FAILED')], default='PENDING', max_length=255)),
                ('type', models.CharField(choices=[('HOST_DISCOVERY', 'Host discovery'), ('FULL_TCP_SCAN', 'Host discovery+1000 TCP Port Scan+ Service Detection+ OS Detection'), ('FULL_UDP_SCAN', 'Host discovery+1000 UDP Port Scan+ Service Detection+ OS Detection'), ('PORT_SCAN_ONLY', '1000 TCP Port Scan+ Service Detection+ OS Detection'), ('ALL_PORT_SCAN_ONLY', 'ALL 65536 TCP Port Scan+ Service Detection+ OS Detection'), ('STEALTHY_SCAN', '100 TCP Stealthy(different given and scrambled segemnts shape, with differet flags as FIN) Port Scan+ Service Detection+ OS Detection'), ('DNS_BRUTE', 'Finds hostname and IP of sub-domains'), ('NETTACKER', 'Finds vulnerabilities using Nettacker server')], default='HOST_DISCOVERY', max_length=255)),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
                ('hosts', models.ManyToManyField(default=[-1], related_name='found_hosts', to='Nmap.host')),
                ('target', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='has_scan_history', to='Nmap.range')),
            ],
        ),
        migrations.CreateModel(
            name='Sub_Domain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, null=True)),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='found_subdomains', to='Nmap.host')),
            ],
            options={
                'ordering': ['-id'],
                'unique_together': {('host', 'name')},
            },
        ),
        migrations.CreateModel(
            name='PortService',
            fields=[
                ('port', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='port_service', serialize=False, to='Nmap.port')),
                ('name', models.CharField(max_length=255, null=True)),
                ('product', models.CharField(max_length=255, null=True)),
                ('extra_info', models.CharField(max_length=255, null=True)),
                ('hostname', models.CharField(max_length=255, null=True)),
                ('operative_system_type', models.CharField(max_length=255, null=True)),
                ('method', models.CharField(max_length=255, null=True)),
                ('conf', models.PositiveSmallIntegerField()),
                ('created_on', models.DateTimeField(auto_now_add=True, help_text='Date and time when the register was created')),
                ('updated_on', models.DateTimeField(auto_now=True, help_text='Date and time when the register was updated')),
            ],
            options={
                'unique_together': {('port', 'name', 'product', 'extra_info', 'hostname', 'operative_system_type', 'method', 'conf')},
            },
        ),
    ]
