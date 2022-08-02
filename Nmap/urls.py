from django.urls import path,include
from . import views
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'projects',viewset=views.ProjectView,basename="projects")
router.register(r'ranges',viewset=views.RangeView,basename="ranges")
router.register(r'history',viewset=views.ScannerHistoryView,basename="history")
router.register(r'subdomains',viewset=views.Sub_DomainView,basename="subdomains")
router.register(r'foundhosts',viewset=views.HostView,basename="foundhosts")
router.register(r'foundports',viewset=views.PortView,basename="foundports")
router.register(r'services',viewset=views.PortServiceView,basename="services")
router.register(r'osmatch',viewset=views.OperativeSystemMatchView,basename="osmatch")
router.register(r'osclass',viewset=views.OperativeSystemClassView,basename="osclass")

app_name = "Nmap"

urlpatterns  = [
    path('',include(router.urls)),
]

# Important URLs for the frontend
# GET
# http://localhost:8000/projects/user_id/
# http://localhost:8000/history/range_id/
# http://localhost:8000/foundhosts/scan_history_id/
# http://localhost:8000/subdomains/host_id/
# http://localhost:8000/osmatch/host_id/
# http://localhost:8000/foundports/host_id/

# POST
# http://localhost:8000/projects/
# http://localhost:8000/ranges/
# http://localhost:8000/history/

# DELETE
# http://localhost:8000/projects/
# http://localhost:8000/ranges/
# http://localhost:8000/history/

# other URLS within ViewSet are all available, some used inside the application