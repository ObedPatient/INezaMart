from django.shortcuts import render, get_object_or_404
from .forms import UserForm, UserProfileForm
from django.shortcuts import HttpResponse,redirect
from Myshopauth.models import Account, UserProfile
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages, auth
# to Activate user accounts
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,force_text, DjangoUnicodeDecodeError

# getting token form utils.py
from .utils import TokenGenerator,generate_token
# email import

from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.mail import BadHeaderError, send_mail
from django.core import mail
from django.conf import settings
from django.core.mail import EmailMessage
#resetpassword generator

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.decorators import login_required
from Carts.views import _cart_id
from Carts.models import Cart, CartItem
from Orders.models import Order, OrderProduct
# threading
import requests
import threading


class EmailThread(threading.Thread):
    def __init__(self,email_message):
        self.email_message=email_message
        threading.Thread.__init__(self)
    def run(self):
        self.email_message.send()



def signup(request):
    if request.method=="POST":
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email=request.POST['email']
        phone_number = request.POST['phone_number']
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        username = email.split('@')[0]

        if password!=confirm_password:
            messages.warning(request, "Password Is Not Matching")
            return render(request, 'auth/signup.html')
        
        try:
            if Account.objects.filter(email=email).exists():
                messages.warning(request, "Email is Taken")
                return render(request,'auth/signup.html')

        except Exception as identifier:
            pass


        user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
        user.is_active=False
        user.save()
        current_site= get_current_site(request)
        email_subject = "Activate Your Account"
        message = render_to_string('auth/activate.html',{
            'user':user,
            'domain':'127.0.0.1:8000',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        })

        email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email],)



        EmailThread(email_message).start()
        messages.info(request, "Activate Your Account By Clicking link on your Email")
        return redirect('/Myshopauth/login')
    return render(request, 'auth/signup.html')

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid= force_text(urlsafe_base64_decode(uidb64))
            user=Account.objects.get(pk=uid)
        except Exception as identifier:
            user=None

        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/Myshopauth/login')

        return render(request,'auth/activatefail.html')

def handlelogin(request):
    if request.method=='POST':
        username=request.POST['email']
        userpassword=request.POST['pass1']
        myuser=authenticate(username=username,password=userpassword)



        if myuser is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists = CartItem.objects.filter(cart=cart).exists()
                if is_cart_item_exists:
                    cart_item = CartItem.objects.filter(cart=cart)
                    request.session['cart_id'] = cart.id
                    
                    # Getting the product variation by cart_id
                    product_variation = []
                    for item in cart_item:
                        variation = item.variations.all()
                        product_variation.append(list(variation))



                    # Get the cart items from user to access his product variations

                    cart_item = CartItem.objects.filter(user=myuser)
                    ex_var_list = []
                    id = []
                    for item in cart_item:
                        existing_variation = item.variations.all()
                        ex_var_list.append(list(existing_variation))
                        id.append(item.id)


                    for pr in product_variation:
                        if pr in ex_var_list:
                            index = ex_var_list.index(pr)
                            item_id = id[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity += 1
                            item.user = myuser
                            item.save()
                        else:
                            cart_item = CartItem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user = myuser
                                item.save()

                    #for item in cart_item:
                    #    item.user = myuser
                    #    item.save()

            except:
                pass
            auth.login(request,myuser)
            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)               
            except:
                 return redirect('index')

        else:
            messages.error(request, "Invalid Credentials!!")
            return redirect('handlelogin')

    return render(request, 'auth/login.html')


@login_required(login_url = 'login')
def handlelogout(request):
    cart_id = request.session.get('cart_id')

    if cart_id:
        try:
            cart = Cart.objects.get(id=cart_id)
            cart.cart_id = _cart_id(request)
            cart.save()
        except:
            pass

    auth.logout(request)
    return redirect('index')


class RequestRestEmailView(View):
    def get(self,request):
        return render(request,'auth/request-reset-email.html')

    def post(self,request):
        email=request.POST['email']
        user=Account.objects.filter(email=email)

        if user.exists():
            current_site=get_current_site(request)
            email_subject='[Reset Your Password]'
            message=render_to_string('auth/reset-user-password.html',{
                'domain':'127.0.0.1:8000',
                'uid':urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token':PasswordResetTokenGenerator().make_token(user[0])
            })

            email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email])
            EmailThread(email_message).start()


            messages.info(request,"WE HAVE SENT YOU AN EMAIL WITH INSTRUCTIONS ON HOW TO REST A PASSWORD ")
            return render(request,'auth/request-reset-email.html')


class SetNewPasswordView(View): 
    def get(self,request,uidb64,token):
        context = {
            'uidb64':uidb64,
            'token':token
        }
        try:
            user_id=force_text(urlsafe_base64_decode(uidb64))
            user=Account.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                messages.warning(request,"Password Reset Link is Invalid")
                return render(request,'auth/request-reset-email.html')

        except DjangoUnicodeDecodeError as identifier:
            pass

        return  render(request,'auth/set-new-password.html',context)
    
    def post(self,request,uidb64,token):
        context = {
            'uidb64':uidb64,
            'token':token
        }
        password=request.POST['pass1']
        confirm_password=request.POST['pass2']
        if password!=confirm_password:
            messages.warning(request, "Password Is Not Matching")
            return render(request, 'auth/set-new-password.html',context)

        try:
            user_id=force_text(urlsafe_base64_decode(uidb64))
            user=Account.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request,'Password Reset Success Please Login with New Password')
            return redirect('/Myshopauth/login/')
        
        except DjangoUnicodeDecodeError as identifier:
            messages.error(request,'Somthing Went Wrong')
            return render(request, 'auth/set-new-password.html',context)

        return render(request, 'auth/set-new-password.html',context)



@login_required(login_url = 'login')
def dashboard(request):
    order = Order.objects.order_by('-created_at').filter(user_id=request.user.id, is_ordered=True)
    order_count = order.count()

    context = {
        'order_count': order_count,
    }
    return render(request, 'auth/dashboard.html', context )

         


@login_required(login_url = 'login')
def my_orders(request):
    orders = Order.objects.filter(user=request.user, is_ordered=True).order_by('-created_at')
    context = {
        'orders':orders,
    }
    return render(request, 'auth/my_orders.html',context)


@login_required(login_url = 'login')
def edit_profile(request):
    userprofile = get_object_or_404(UserProfile, user=request.user)
    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=request.user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=userprofile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your Profile has been Updated.')
            return redirect('edit_profile')
    else:
        user_form = UserForm(instance=request.user)
        profile_form = UserProfileForm(instance=userprofile)

    context = {
        'user_form':user_form,
        'profile_form': profile_form,
        'userprofile': userprofile,
    }
    return render(request, 'auth/edit_profile.html', context)



@login_required(login_url = 'login')
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']

        user = Account.objects.get(username__exact=request.user.username)

        if new_password == confirm_password:
            success = user.check_password(current_password)
            if success:
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password Updated Successfully.')
                return redirect('handlelogin')
            else: 
                messages.error(request, 'Please Enter Valid Current Password')
                return redirect('change_password')
        else:
            messages.error(request, 'Password Does Not Match')
    return render(request, 'auth/change_password.html' )

@login_required(login_url = 'login')
def order_detail(request, order_id):
    order_detail = OrderProduct.objects.filter(order__order_number=order_id)
    order = Order.objects.get(order_number=order_id)
    total = 0 
    for i in order_detail:
        total += i.product_price * i.quantity
    context = {
        'order_detail': order_detail,
        'order': order,
        'total': total,
    }
    return render(request, 'auth/order_detail.html', context)
