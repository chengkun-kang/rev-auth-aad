
## Authentication with Azure Active Directory(AAD)
======

#Usage:
Include module in app.conf

```
module.revauthaad=github.com/chengkun-kang/rev-auth-aad
```

Include module in conf/routes

```
module:revauthaad
```


# Add application environments before start/during deployment
The cloud instance (Instance) if you want your app to run in national clouds, for example. The different options include;
```
https://login.microsoftonline.com/ for Azure public cloud
https://login.microsoftonline.us/ for Azure US government
https://login.microsoftonline.de/ for Azure AD Germany
https://login.partner.microsoftonline.cn/common for Azure AD China operated by 21Vianet
```