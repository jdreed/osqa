import json

from consumer import OIDCAbstractAuthConsumer
from forum.authentication.base import ConsumerTemplateContext

# The classes must end in AuthConsumer and AuthContext
# and must match.  Go look in forum.authentication and forum.modules

class MITAuthConsumer(OIDCAbstractAuthConsumer):
    def __init__(self):
        OIDCAbstractAuthConsumer.__init__(self,
                                          'CLIENT ID HERE',
                                          'CLIENT SECRET HERE',
                                          'REDIRECT_URI_HERE',
                                          'https://oidc.mit.edu')

class MITAuthContext(ConsumerTemplateContext):
    mode = 'BIGICON'
    type = 'DIRECT'
    weight = 400
    human_name = 'MIT'
    icon = '/media/images/openid/mit_openid.png'
