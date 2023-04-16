from django.urls import path
from Myshopauth import views

urlpatterns = [
    path('signup/', views.signup,name='signup'),
    path('login/', views.handlelogin,name='handlelogin'),
    path('logout/', views.handlelogout,name='handlelogout'),
    path('activate/<uidb64>/<token>', views.ActivateAccountView.as_view(),name='activate'),
    path('request-reset-email/', views.RequestRestEmailView.as_view(),name='request-reset-email'),
    path('set-new-password/<uidb64>/<token>', views.SetNewPasswordView.as_view(),name='set-new-password'),
    path('dashboard/', views.dashboard, name='dashboard'),
    

    path('my_orders/', views.my_orders, name='my_orders'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('order_detail/<int:order_id>/', views.order_detail, name='order_detail'),
]