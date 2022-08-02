from rest_framework import viewsets
from rest_framework.response import Response
from django.db.models import F
from rest_framework.decorators import api_view, permission_classes

from .models import (
    Project,
    Range,
    Host,
    OperativeSystemMatch,
    OperativeSystemClass,
    Port,
    PortService,
    ScannerHistory,
    Sub_Domain
)
from .serializers import(
    ProjectSerializer,
    RangeSerializer,
    HostSerializer,
    OperativeSystemMatchSerializer,
    OperativeSystemClassSerializer,
    PortSerializer,
    PortServiceSerializer,
    ScannerHistorySerializer,
    Sub_DomainSerializer,
)

class ProjectView(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    def retrieve(self, request,*args,**kwargs):
        # http://localhost:8000/projects/user_id/
        params = kwargs
        projects = Project.objects.filter(user=params['pk'])
        serializer = ProjectSerializer(projects,many=True)
        if projects.count() == 0:
            return Response({"message":"No projects is created yet"})
        else:
            return Response({"projects":serializer.data})

class RangeView(viewsets.ModelViewSet):
    queryset = Range.objects.all()
    serializer_class = RangeSerializer

class HostView(viewsets.ModelViewSet):
    queryset = Host.objects.all()
    serializer_class = HostSerializer
    def retrieve(self, request,*args,**kwargs):
        # http://localhost:8000/foundhosts/scan_history_id/
        params = kwargs
        hosts = Host.objects.filter(found_hosts=params['pk'])
        serializer = HostSerializer(hosts,many=True)
        if hosts.count() == 0:
            return Response({"message":"No hosts is found yet"})
        else:
            return Response({"hosts":serializer.data})

class OperativeSystemMatchView(viewsets.ModelViewSet):
    queryset = OperativeSystemMatch.objects.all()
    serializer_class = OperativeSystemMatchSerializer
    def retrieve(self, request,*args,**kwargs):
        # http://localhost:8000/osmatch/host_id/
        params = kwargs
        found_matches = OperativeSystemMatch.objects.filter(host_id=params['pk'])
        serializer = OperativeSystemMatchSerializer(found_matches,many=True)
        if found_matches.count() == 0:
            return Response({"message":"No OS matches is done or found yet"})
        else:
            return Response({"found_matches":serializer.data})
        
        
class OperativeSystemClassView(viewsets.ModelViewSet):
    queryset = OperativeSystemClass.objects.all()
    serializer_class = OperativeSystemClassSerializer

class PortView(viewsets.ModelViewSet):
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    def retrieve(self, request,*args,**kwargs):
        # http://localhost:8000/foundports/host_id/
        params = kwargs
        foundports = Port.objects.filter(host_id=params['pk'])
        serializer = PortSerializer(foundports,many=True)
        if foundports.count() == 0:
            return Response({"message":"No ports is found yet"})
        else:
            return Response({"foundports":serializer.data})

class PortServiceView(viewsets.ModelViewSet):
    queryset = PortService.objects.all()
    serializer_class = PortServiceSerializer

class Sub_DomainView(viewsets.ModelViewSet):
    queryset = Sub_Domain.objects.all()
    serializer_class = Sub_DomainSerializer
    def retrieve(self, request,*args,**kwargs):
        # http://localhost:8000/subdomains/host_id/
        params = kwargs
        subdomains = Sub_Domain.objects.filter(host_id=params['pk'])
        subdomains_serializer = Sub_DomainSerializer(subdomains, many=True)
        if subdomains.count() == 0:
            return Response({"message":"No sub-domains scan is done yet on the given range"})
        else:
            return Response({"subdomains":subdomains_serializer.data})
class ScannerHistoryView(viewsets.ModelViewSet):
    queryset = ScannerHistory.objects.all()
    serializer_class = ScannerHistorySerializer
    
    def retrieve(self, request,*args,**kwargs):
        # http://localhost:8000/history/range_id/
        params = kwargs
        history_data = ScannerHistory.objects.filter(target=params['pk'])
        history_serializer = ScannerHistorySerializer(history_data, many=True)
        if history_data.count() == 0:
            return Response({"message":"No scans is done yet on the given range"})
        else:
            return Response({"history":history_serializer.data})

    def create(self, request):
        serializer = ScannerHistorySerializer(data=request.data)
        if serializer.is_valid():
            scannerhistory = serializer.save()
            return Response({"message":"Successfully scanned the target"})
        else:
            data = serializer.errors
            return Response(data)
