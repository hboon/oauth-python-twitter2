#!/usr/bin/env python
# 
# Copyright under  the latest Apache License 2.0

'''
A modification of the python twitter oauth library by Hameedullah Khan.
Instead of inheritance from the python-twitter library, it currently
exists standalone with an all encompasing ApiCall function. There are
plans to provide wrapper functions around common requests in the future.

Requires:
  simplejson
  oauth
'''

__author__ = "Konpaku Kogasa, Hameedullah Khan <hameed@hameedkhan.net>"
__version__ = "0.1"

import simplejson
import urllib
import urllib2
from oauth import oauth

# Taken from oauth implementation at: http://github.com/harperreed/twitteroauth-python/tree/master
REQUEST_TOKEN_URL = 'https://twitter.com/oauth/request_token'
ACCESS_TOKEN_URL = 'https://twitter.com/oauth/access_token'
AUTHORIZATION_URL = 'http://twitter.com/oauth/authorize'
SIGNIN_URL = 'http://twitter.com/oauth/authenticate'


class OAuthApi():
    def __init__(self, consumer_key, consumer_secret, token, token_secret):
    	if token and token_secret:
    		token = oauth.OAuthToken(token, token_secret)
    	else:
    		 token = None
        self._Consumer = oauth.OAuthConsumer(consumer_key, consumer_secret)
        self._signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        self._access_token = token 

    def _GetOpener(self):
        opener = urllib2.build_opener()
        return opener

    def _FetchUrl(self,
                    url,
                    http_method=None,
                    parameters=None):
        '''Fetch a URL, optionally caching for a specified time.
    
        Args:
          url: The URL to retrieve
          http_method: 
          	One of "GET" or "POST" to state which kind 
          	of http call is being made
          parameters:
            A dict whose key/value pairs should encoded and added 
            to the query string, or generated into post data. [OPTIONAL]
            depending on the http_method parameter
    
        Returns:
          A string containing the body of the response.
        '''
        # Build the extra parameters dict
        extra_params = {}
        if parameters:
          extra_params.update(parameters)
        
        req = self._makeOAuthRequest(url, parameters=extra_params, 
                                                    http_method=http_method)
        self._signRequest(req, self._signature_method)

        
        # Get a url opener that can handle Oauth basic auth
        opener = self._GetOpener()

        if http_method == "POST":
            encoded_post_data = req.to_postdata()
            url = req.get_normalized_http_url()
        else:
            url = req.to_url()
            encoded_post_data = ""
            
        if encoded_post_data:
        	url_data = opener.open(url, encoded_post_data).read()
        else:
        	url_data = opener.open(url).read()
        	opener.close()
    
        # Always return the latest version
        return url_data
    
    def _makeOAuthRequest(self, url, token=None,
                                        parameters=None, http_method="GET"):
        '''Make a OAuth request from url and parameters
        
        Args:
          url: The Url to use for creating OAuth Request
          parameters:
             The URL parameters
          http_method:
             The HTTP method to use
        Returns:
          A OAauthRequest object
        '''
        if not token:
            token = self._access_token
        request = oauth.OAuthRequest.from_consumer_and_token(
                            self._Consumer, token=token, 
                            http_url=url, parameters=parameters, 
                            http_method=http_method)
        return request

    def _signRequest(self, req, signature_method=oauth.OAuthSignatureMethod_HMAC_SHA1()):
        '''Sign a request
        
        Reminder: Created this function so incase
        if I need to add anything to request before signing
        
        Args:
          req: The OAuth request created via _makeOAuthRequest
          signate_method:
             The oauth signature method to use
        '''
        req.sign_request(signature_method, self._Consumer, self._access_token)
    

    def getAuthorizationURL(self, token, url=AUTHORIZATION_URL):
        '''Create a signed authorization URL
        
        Returns:
          A signed OAuthRequest authorization URL 
        '''
        req = self._makeOAuthRequest(url, token=token)
        self._signRequest(req)
        return req.to_url()

    def getSigninURL(self, token, url=SIGNIN_URL):
        '''Create a signed Sign-in URL
        
        Returns:
          A signed OAuthRequest Sign-in URL 
        '''
        
        signin_url = self.getAuthorizationURL(token, url)
        return signin_url
    
    def getAccessToken(self, url=ACCESS_TOKEN_URL):
        token = self._FetchUrl(url, no_cache=True)
        return oauth.OAuthToken.from_string(token) 

    def getRequestToken(self, url=REQUEST_TOKEN_URL):
        '''Get a Request Token from Twitter
        
        Returns:
          A OAuthToken object containing a request token
        '''
        resp = self._FetchUrl(url, no_cache=True)
        token = oauth.OAuthToken.from_string(resp)
        return token
    
    def ApiCall(self, call, type="GET", parameters={}):
        '''Calls the twitter API
        
       Args:
          call: The name of the api call (ie. account/rate_limit_status)
          type: One of "GET" or "POST"
          parameters: Parameters to pass to the Twitter API call
        Returns:
          Returns the twitter.User object
        '''
        json = self._FetchUrl("https://api.twitter.com/1/" + call + ".json", type, parameters)
        return simplejson.loads(json)
