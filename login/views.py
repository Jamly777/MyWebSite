from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response
from rest_framework.views import APIView
from Jamly import settings
from . import models
from django.core.cache import cache
from django.core import signing
import hashlib
import time

#读取数据库数据，存入redis
def get_usrInfo_from_mysql():
    usrInfo=[]
    queries=models.User.objects.all()
    for query in queries:
        usrInfo.append({
            "id":query.id,"username":query.username,
            "password":query.password
        })
    cache.set('usrInfo',usrInfo)

def encrypt(obj):
    value=signing.dumps(obj,key=settings.key,salt=settings.salt)
    value=signing.b64_encode(value.encode()).decode()
    return value

#解密
def decrpyt(src):
    src=signing.b64_decode(src.encode()).decode()
    raw=signing.loads(src,key=settings.key,salt=settings.salt)
    return raw

#token
def create_token(openid):
    header = encrypt(settings.HEADER)
    payload = {'userid': openid, 'iat': time.time()}
    payload = encrypt(payload)
    md5 = hashlib.md5()
    md5.update(("{0}.{1}".format(header, payload)).encode())
    signature = md5.hexdigest()
    token = '{0}.{1}.{2}'.format(header, payload, signature)
    return token

#token验证
def get_userid(token):
    if token != '':
        payload = str(token).split('.')[1]
        payload = decrpyt(payload)
        userid=payload['userid']
        return userid
    else:
        return token

# Create your views here.
def index(request):
    return render(request,'Loading.html')

@csrf_exempt #跳过csrf的保护
def login(request):
    if request.method == 'GET':
        return render(request,'Login.html')

def picture(request):
    if request.method == 'GET':
        return render(request,'picture.html')

class check(APIView):
    def post(self,request):
        while cache.get('usrInfo') is None:
            get_usrInfo_from_mysql()
        usrInfos=cache.get('usrInfo')
        username = request.POST['name']
        password = request.POST['password']
        if username in [usrInfo['username'] for usrInfo in usrInfos]:
            pass_in_sql=decrpyt([usrInfo['password'] for usrInfo in usrInfos if usrInfo['username']==username][0])
            if cache.get(username+'unlock') == False:
                res={
                    "code":300,
                    "msg":'此账号已被冻结，请稍后再试'
                }
            else:
                if cache.get(username+'count') is None:
                    cache.set(username+'count',0,60*60)
                if cache.get(username+'count') < 5:
                    if password == pass_in_sql:
                        token=create_token(username)
                        cache.set(username+'count',0,60*60)
                        cache.set(username,token,60*60*24)
                        res={
                            "code":200,
                            "token":token
                        }
                    else:
                        res={
                            "code":400,
                            "msg":'密码错误'
                        }
                        count = cache.get(username+'count')+1
                        cache.set(username+'count',count,60*60)
                elif cache.get(username + 'count') >= 5 and cache.get(username + 'count') < 15:
                    if password == pass_in_sql:
                        token=create_token(username)
                        cache.set(username+'count',0,60*60)
                        cache.set(username,token,60*60*24)
                        res={
                            "code":200,
                            "token":token
                        }
                    else:
                        res={
                            "code":400,
                            "msg":'密码错误,账号冻结，请5min后重试'
                        }
                        count=cache.get(username+'count')+1
                        cache.set(username+'count',count,60*60)
                        cache.set(username+'unlock',False,60*5)
                elif cache.get(username + 'count') >= 15 and cache.get(username + 'count') < 30:
                    if password == pass_in_sql:
                        token=create_token(username)
                        cache.set(username+'count',0,60*60)
                        cache.set(username,token,60*60*24)
                        res={
                            "code":200,
                            "token":token
                        }
                    else:
                        res={
                            "code":400,
                            "msg":'密码错误,账号冻结，请5min后重试'
                        }
                        count=cache.get(username+'count')+1
                        cache.set(username+'count',count,60*60)
                        cache.set(username+'unlock',False,60*30)
                else:
                    if password == pass_in_sql:
                        token=create_token(username)
                        cache.set(username+'count',0,60*60)
                        cache.set(username,token,60*60*24)
                        res={
                            "code":200,
                            "token":token
                        }
                    else:
                        res={
                            "code":400,
                            "msg":'密码错误,账号冻结，请5min后重试'
                        }
                        count=cache.get(username+'count')+1
                        cache.set(username+'count',count,60*60)
                        cache.set(username+'unlock',False,60*60*24)
        else:
            res={
                "code":404,
                "msg":'此账号不存在，请注册后登陆'
            }
        return Response(res)


class register(APIView):
    def post(self,request):
        while cache.get('usrInfo') is None:
            get_usrInfo_from_mysql()
        usrInfos=cache.get('usrInfo')
        username = request.POST['name']
        password = request.POST['password']
        if username not in [usrInfo['username'] for usrInfo in usrInfos]:
            password_on=encrypt(password)
            models.User.objects.create(username=username,password=password_on)
            cache.delete('usrInfo')
            res={
                "code":200
            }
        else:
            res={
                "code":400,
                "msg":'此用户已注册'
            }
        return Response(res)