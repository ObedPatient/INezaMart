from django.urls import path
from . import views

urlpatterns = [
    path('', views.purchase, name='purchase'),
    path('<slug:category_slug>', views.purchase, name='product_by_category'),
    path('<slug:category_slug>/<slug:product_slug>/', views.product_detail, name='product_detail'),
]