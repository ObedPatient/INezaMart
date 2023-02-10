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
    
]