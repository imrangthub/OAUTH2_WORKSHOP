# OAUTH2_WORKSHOP
For self-learning and practice


ClientCredentials:GrantType
------------------------------------------------------

GET:

    curl --location 'http://localhost:9000/oauth2/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Authorization: Basic b2lkYy1jbGllbnQ6c2VjcmV0' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode 'scope=profile'



AuthorizationCode:GrantType
------------------------------------------------------
1) Request for code
   GET
   
       http://localhost:9000/oauth2/authorize?response_type=code&client_id=myclientid&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/myclient&scope=profile


1) Response with code:

       http://127.0.0.1:8080/login/oauth2/code/myclient?code=
       0DfBufb2RNLkgE74lN3hEw92YuZ6IBnJXb9TrElJ_VW2EYY58gnYGhnOcN8QTf4blzeDI_Vog1pAkbDrTdfq4g0Vh-iAfh2IJXm_zVt70JAGn52eq5UWDXKYFju1GCWF



4) Exchange the Authorization Code for token

POST:

    curl --location 'http://localhost:9000/oauth2/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --header 'Authorization: Basic bXljbGllbnRpZDpteWNsaWVudHNlYw==' \
    --header 'Cookie: JSESSIONID=28E4B4AA8867A380AC7B4873F6429708' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode 'redirect_uri=http://127.0.0.1:8080/login/oauth2/code/myclient' \
    --data-urlencode 'code=0DfBufb2RNLkgE74lN3hEw92YuZ6IBnJXb9TrElJ_VW2EYY58gnYGhnOcN8QTf4blzeDI_Vog1pAkbDrTdfq4g0Vh-iAfh2IJXm_zVt70JAGn52eq5UWDXKYFju1GCWF' \
    --data-urlencode 'client_id=myclientid' \
    --data-urlencode 'client_secret=myclientsec'





Spring Boot Web application with GitHub OAuth support
------------------------------------------------------

Steps:

    1) Create a GitHub App and get the Client ID and Client Secret values. (Specify callback URL as http://localhost:8080/login/oauth2/code/github for development, uncheck Web hooks)
    2) Add those values in application.yml
    3)  Run the Spring Boot App. You should be able to login with GitHub
   
Post login, you will be redirected back to the login page, but you can validate the authorized principal is created by accessing the /user API.
