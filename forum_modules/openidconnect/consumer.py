import urllib
import urllib2
import httplib
import time
import logging

from forum.settings import APP_URL
from forum.authentication.base import AuthenticationConsumer, InvalidAuthentication
from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse
from oic import oic
from oic.oic import message
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oauth2 import rndstr
from forum.models import User
from forum.actions import UserJoinsAction

class OIDCAbstractAuthConsumer(AuthenticationConsumer):

    def __init__(self, client_id, client_secret, redirect_uri, server_url):
        self.client_secret = client_secret
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client = oic.Client(client_id=client_id,
                                 client_authn_method=CLIENT_AUTHN_METHOD)
        # Why the library cannot simply be passed a server URL and
        # do all the right stuff with it is beyond me
        pc = self.client.provider_config(server_url)
        # This is hardcoded in oic.oauth2.message as the empty string,
        # I have no idea why.
        self.client.keyjar.load_keys(pc, '')
        self.scopes_desired = ['openid', 'profile', 'email']

    def prepare_authentication_request(self, request, redirect_to):
        # We do not use redirect_to here, it redirects to the "done" URL of the
        # auth provider
        # Set a state and nonce and save them in the session
        request.session['state'] = rndstr()
        request.session['nonce'] = rndstr()
        request_args = {'response_type': 'code',
                        'scope': ' '.join(self.scopes_desired),
                        'redirect_uri': self.redirect_uri,
                        'nonce': request.session['nonce'],
                        'state': request.session['state'] }
        # Generate the components of the authorization request
        uri, body, http_args, areq = self.client.authorization_request_info(request_args=request_args)
        return uri

    def process_authentication_request(self, request):
        authresp = self.client.parse_response(message.AuthorizationResponse,
                                              info=request.GET,
                                              sformat="dict")
        assert authresp["state"] == request.session['state']
        if 'error' in request.GET:
            raise InvalidAuthentication('OIDC error:' + request.GET['error_description'])
        if 'code' not in request.GET:
            raise InvalidAuthentication('Unexpected response from OIDC server')
        request_args = { 'client_id' : self.client_id,
                         'client_secret': self.client_secret,
                         'code': authresp['code'],
                         'redirect_uri': self.redirect_uri }
        token = self.client.do_access_token_request(request_args=request_args,
                                                    state=authresp['state'],
                                                    authn_method="client_secret_post")
        if set(token['scope']).intersection(set(self.scopes_desired)) != set(self.scopes_desired):
            raise InvalidAuthentication('OIDC error: You denied access to one or more required scopes')
        userinfo = self.client.do_user_info_request(state=authresp['state'])
        try:
            user = User.objects.get(email=userinfo['email'])
        except User.DoesNotExist:
            user = User(username=userinfo['preferred_username'],
                        email=userinfo['email'])
            # Not sure if all providers will set this?
            user.email_isvalid = userinfo.get('email_verified', False)
            user.set_unusable_password()
            user.save()
            UserJoinsAction(user=user, ip=request.META['REMOTE_ADDR']).save()
        return user

    def get_user_data(self, key):
        return {}
