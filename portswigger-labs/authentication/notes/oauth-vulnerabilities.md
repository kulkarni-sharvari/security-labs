# OAuth 2.0 authentication vulnerabilities

## What is OAuth?
- OAuth = authorization framework
- Allows websites/web apps to request limited access to a user’s account on another application
- Does not require sharing login credentials with the requesting app
- Users can:
    - Control what data they share
    - Give limited permissions
    - Avoid giving a third party full account access
- Example:
    - An app requests access to your email contacts
    - Uses the contacts to suggest people you may know/connect with

## How does OAuth 2.0 work?
- Involved parties:
    - Client application: Requesting webapp
    - Resource owner: The user
    - Oauth Service provider: The webapp that controls the user data and it's access. They support OAuth by providing API for interacting with both an authorization sercer and a resource server.
- Steps
1. Client application requests access to a subset of user's data, specifying the `grant type`
2. User is prompted to login to Oauth service and explicitly give their consent for the requested access
3. The client application receives a unique access token that proves they have permissions from the user to access the requested data. 
4. The client application uses this access token to make the API call to fetch the data from resource server

### Grant types
1. Authorization code
       User     
        |       
    Client Application      
        |       
        | Authorization code    
        |   
    Authorization Server    
        |   
        | Authorization access token    
        |   
    User login and consent  
        |   
    Token endpoint  
        |   
    Resource Server/API     

2. Implicit Grant:
           User     
            |    
        Client Applicatio       
            |   
            | Access Token  
            |   
        Authorization  Server   
            |   
            | Protected Resource    
            |   
        User login and consent  
            |   
        Resource Server/API 

