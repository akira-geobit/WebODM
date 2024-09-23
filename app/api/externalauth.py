from django.contrib.auth.models import User
from django.contrib.auth import login
from rest_framework.views import APIView
from rest_framework import exceptions, permissions, parsers
from rest_framework.response import Response
from app.auth.backends import get_user_from_external_auth_response
import requests
from webodm import settings
import jwt
class ExternalTokenAuth(APIView):
    permission_classes = (permissions.AllowAny,)
    parser_classes = (parsers.JSONParser, parsers.FormParser,)

    def post(self, request):
        token = request.query_params.get('jwt', '')
        if token == '':
            return Response({'error': 'external_access_token cookie not set'}, status=400)

        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            sender_id = payload.get('user_id')
            if sender_id is None:
                return Response({'error': 'Invalid token payload'}, status=400)
            return Response({'redirect': settings.LOGIN_REDIRECT_URL})
        
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token has expired'}, status=401)
        except jwt.DecodeError:
            return Response({'error': 'Invalid token'}, status=400)
        except Exception as e:
            return Response({'error': str(e)}, status=500)

