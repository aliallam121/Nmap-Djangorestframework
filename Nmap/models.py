from django.db import models
from django.forms import ValidationError
import socket
# Source: Model field reference https://docs.djangoproject.com/en/3.1/ref/models/fields/#module-django.db.models.fields
class Project(models.Model):
    name = models.CharField(
        max_length=255,unique=True
    )
    priority = models.PositiveSmallIntegerField()
    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )
    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )
    
    class Meta:
        ordering = ['-priority']
        
class Range(models.Model):
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='has_ranges'
    )
    domain_name = models.CharField(
        max_length=255,null=True,default='unkown',blank=True
    )
    ip_range = models.GenericIPAddressField(verbose_name=("target address"))
    mask = models.IntegerField(verbose_name="Mask", default=32)
    given = models.CharField(
        max_length=255,null=True,default='ip',blank=True
    )
    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )
    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )
    class Meta:
        ordering = ['-created_on']
        
    def save(self, *args, **kwargs):
        if self.domain_name is not None and (self.ip_range is None or self.ip_range=="0.0.0.0"):
            self.ip_range = socket.gethostbyname(self.domain_name)
            self.given = 'name'
            super(Range, self).save(*args, **kwargs)
        else:
            self.given = 'ip'
            super(Range, self).save(*args, **kwargs)
    def clean(self):
        super().clean()
        if (self.ip_range is None or self.ip_range=="0.0.0.0") and self.domain_name is None:
            raise ValidationError('Ip Range or Domain Name are None')
        

class Host(models.Model):
    ip = models.GenericIPAddressField()
    mac_address = models.CharField(
        max_length=20,
        null=True
    )
    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )
    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )
    class Meta:
        ordering = ['-created_on']

class OperativeSystemMatch(models.Model):
    name = models.CharField(
        max_length=255
    )
    accuracy = models.PositiveSmallIntegerField()
    line = models.PositiveSmallIntegerField()
    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='has_possible_os_match'
    )
    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )
    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )
    class Meta:
        ordering = ['-created_on']

class OperativeSystemClass(models.Model):

    operative_system_match = models.OneToOneField(
        OperativeSystemMatch,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='specs'
    )

    type = models.CharField(
        max_length=255
    )

    vendor = models.CharField(
        max_length=255
    )

    operative_system_family = models.CharField(
        max_length=255
    )

    operative_system_generation = models.CharField(
        max_length=255
    )

    accuracy = models.PositiveSmallIntegerField()

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

class Port(models.Model):

    protocol = models.CharField(
        max_length=255
    )

    port_number = models.PositiveSmallIntegerField()

    state = models.CharField(
        max_length=255
    )

    reason = models.CharField(
        max_length=255
    )

    reason_ttl = models.PositiveSmallIntegerField()

    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='host_ports'
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

    class Meta:
        ordering = ['-port_number']
        unique_together = ('protocol', 'port_number','host','state','reason_ttl')

class PortService(models.Model):
    port = models.OneToOneField(
        Port,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='port_service'
    )

    name = models.CharField(
        max_length=255,
        null=True
    )

    product = models.CharField(
        max_length=255,
        null=True
    )

    extra_info = models.CharField(
        max_length=255,
        null=True
    )

    hostname = models.CharField(
        max_length=255,
        null=True
    )

    operative_system_type = models.CharField(
        max_length=255,
        null=True
    )

    method = models.CharField(
        max_length=255,
        null=True
    )

    conf = models.PositiveSmallIntegerField()

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )
    class Meta:
        unique_together = ('port', 'name','product','extra_info','hostname','operative_system_type','method','conf')

class ScannerHistory(models.Model):
    target = models.ForeignKey(
        Range,
        on_delete=models.CASCADE,
        related_name='has_scan_history'
    )
    scanname = models.CharField(
        max_length=255,
        unique=True
    )
    # Choices for status
    PENDING = 'PENDING'
    FINISHED = 'FINISHED'
    FAILED = 'FAILED'
    TYPE_CHOICES = [
        (PENDING, 'PENDING'),
        (FINISHED, 'FINISHED'),
        (FAILED, 'FAILED'),
    ]
    status = models.CharField(
        choices=TYPE_CHOICES,
        default=PENDING,
        max_length=255,
    )
    
    hosts = models.ManyToManyField(
        Host,
        related_name='found_hosts',
        default=[-1],
    )
    # Choices for field type
    HOST_DISCOVERY = 'HOST_DISCOVERY'
    FULL_TCP_SCAN = 'FULL_TCP_SCAN'
    FULL_UDP_SCAN = 'FULL_UDP_SCAN'
    PORT_SCAN_ONLY = 'PORT_SCAN_ONLY'
    ALL_PORT_SCAN_ONLY = 'ALL_PORT_SCAN_ONLY'
    DNS_BRUTE = 'DNS_BRUTE'
    STEALTHY_SCAN = 'STEALTHY_SCAN'
    NETTACKER = 'NETTACKER'
    # NSE_SCAN = 'NSE_SCAN'
    TYPE_CHOICES = [
        (HOST_DISCOVERY, 'Host discovery'),
        (FULL_TCP_SCAN, 'Host discovery+1000 TCP Port Scan+ Service Detection+ OS Detection'),
        (FULL_UDP_SCAN, 'Host discovery+1000 UDP Port Scan+ Service Detection+ OS Detection'),
        (PORT_SCAN_ONLY, '1000 TCP Port Scan+ Service Detection+ OS Detection'),
        (ALL_PORT_SCAN_ONLY, 'ALL 65536 TCP Port Scan+ Service Detection+ OS Detection'),
        (STEALTHY_SCAN, '100 TCP Stealthy(different given and scrambled segemnts shape, with differet flags as FIN) Port Scan+ Service Detection+ OS Detection'),
        (DNS_BRUTE, 'Finds hostname and IP of sub-domains'),
        (NETTACKER, 'Finds vulnerabilities using Nettacker server'),
        # (NSE_SCAN, 'using NSE scripts'),
    ]

    type = models.CharField(
        choices=TYPE_CHOICES,
        default=HOST_DISCOVERY,
        max_length=255,
    )

    created_on = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time when the register was created"
    )

    updated_on = models.DateTimeField(
        auto_now=True,
        help_text="Date and time when the register was updated"
    )

class Sub_Domain(models.Model):
        host = models.ForeignKey(
            Host,
            on_delete=models.CASCADE,
            related_name='found_subdomains'
        )
        name = models.CharField(
            max_length=255,
            null=True
        )
        created_on = models.DateTimeField(
            auto_now_add=True,
            help_text="Date and time when the register was created"
        )

        updated_on = models.DateTimeField(
            auto_now=True,
            help_text="Date and time when the register was updated"
        )
        class Meta:
            ordering = ['-id']
            unique_together = ('host','name')
        