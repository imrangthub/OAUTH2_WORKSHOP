# OAUTH2_WORKSHOP
For self-learning and practice


ClientCredentials:GrantType
------------------------------------------------------

GET:

       curl --location 'http://localhost:9000/oauth2/token' \
        --header 'Content-Type: application/x-www-form-urlencoded' \
        --header 'Authorization: Basic bXljbGllbDpteWNsaWVudHNlYw==' \
        --data-urlencode 'grant_type=client_credentials' \
        --data-urlencode 'scope=read profile'



AuthorizationCode:GrantType
------------------------------------------------------
1) Request for code
   GET

       http://localhost:9000/oauth2/authorize?response_type=code&client_id=spring-boot-client-app&redirect_uri=http://localhost:7070/callback&scope=read+profile

With PKCE:

      http://localhost:9000/oauth2/authorize?response_type=code&client_id=spring-boot-client-app&redirect_uri=http://localhost:7070/callback&scope=read+profile&code_challenge=s-xbMA37ZWdCGEQjOO03Hen_WaKqhH_TQ8c-FhM0k4o&code_challenge_method=S256


2) Response with code: `

       http://127.0.0.1:8080/login/oauth2/code/myclient?code= 0DfBufb2RNLkgE74lN3hEw9Vt70JAGn52eq5UWDXKYFju1GCWF
   

3) Exchange the Authorization Code for token

POST:

    curl --location 'http://localhost:9000/oauth2/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Authorization: Basic bXljbGllbnRppteWNsaWVudHNlYw==' \
    --header 'Cookie: JSESSIONID=28E4B4AA8867A380AC7B4873F6429708' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode 'redirect_uri=http://127.0.0.1:8080/login/oauth2/code/myclient' \
    --data-urlencode 'code=0DfBufb2RNLkgE74lN3zVt70JAGn52eq5UWDXKYFju1GCWF' \
    --data-urlencode 'client_id=myclientid' \
    --data-urlencode 'client_secret=myclientsec'
    

POST:WITH-PKCE:

      curl --location 'http://localhost:9000/oauth2/token' \
      --header 'Content-Type: application/x-www-form-urlencoded' \
      --header 'Authorization: Basic c3ByaW5nLWJvb3QtY2xpZW5jbGllbnQtYXBwLXNlYw==' \
      --data-urlencode 'grant_type=authorization_code' \
      --data-urlencode 'redirect_uri=http://localhost:7070/callback' \
      --data-urlencode 'code=RmlSYNYPOzjHk4]oXqv3RFAU8Tom49Y8rd_hl98Ti' \
      --data-urlencode 'code_verifier=b0473b35778f41b987413c28db04b163'
    


  



OAuth2 doc:
------------------------------------------------------

Key Components of OAuth 2.0:

      Resource Owner: The user who authorizes access to their data.
    
      Client (Application): The third-party app requesting access (e.g., a weather app asking for your location data).
    
      Resource Server: The server hosting the user’s data (e.g., Google’s servers).
    
      Authorization Server: Issues access tokens after the user grants permission (e.g., Google Authorization Server).


OAuth grant types:

    Authorization code
    Client credentials
    Device code
    Password Grant (Resource Owner Password Credentials, Legacy grant types)
    Implicit grant (Legacy grant types:)


Token type:

    Access Token:  Used to access protected resources.
    
    Refresh Token: Used to obtain a new access token when the old one expires.
    
    ID Token (in OpenID Connect): Contains user identity information (e.g., name, email).
    
    Opaque Token (UUID Token):  A random, non-readable token that requires server-side validation (often represented as a UUID).
    



