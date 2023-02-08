
## Authentication with Azure Active Directory(AAD)
======

#Usage:
Include module in Revel Application file: conf/app.conf

```
module.revauthaad=github.com/chengkun-kang/rev-auth-aad
```

Include module in Revel Application file: conf/routes

```
module:revauthaad
```

Incude revel config variables in Revel Application file conf/app.conf
```
aad.tenant.id=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx
aad.app.client.id=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx
aad.app.client.secret=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx
aad.cloud.instance=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx          # default: https://login.microsoftonline.com
aad.api.public.scopes=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx       # default: User.Read
aad.api.credential.scopes=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx   # default: https://graph.microsoft.com/.default
aad.account.primary.domain=xxxxxxxxxxxxxxxxxxxxxxxxxxxx        # default: sanofi.com
app.logout.redirect.url=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx         # default: /login
```


# Add application environments before start/during deployment
The cloud instance (Instance) if you want your app to run in national clouds, for example. The different options include;
```
https://login.microsoftonline.com/ for Azure public cloud
https://login.microsoftonline.us/ for Azure US government
https://login.microsoftonline.de/ for Azure AD Germany
https://login.partner.microsoftonline.cn/common for Azure AD China operated by 21Vianet
```

