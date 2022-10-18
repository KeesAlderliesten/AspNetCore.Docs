---
title: Configuring authentication for minimal APIs
author: safia
description: Learn how to configure authentication and authorization in minimal API apps
ms.author: safia
monikerRange: '>= aspnetcore-7.0'
ms.date: 10/17/2022
uid: fundamentals/minimal-apis/security
---

Minimal APIs support the full spectrum of authentication and authorization options availalbe in ASP.NET and provide some additional functionality to improve the experience for working with authentication.

## Key concepts in authentication and authorization

Authentication is the process of determining a user's identity. Authorization is the process of determining whether a user has access to a resource. Both authentication and authorization scenarios share similar implementation semantics in ASP.NET Core. Authentication is handled by the authentication service, [IAuthenticationService](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.iauthenticationservice), which is used by authentication [middleware](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-6.0). Authorization is handled by the authroziation service, IAuthorizationService, which is used by the authroization middleware.

The authentication service uses registered authentication handlers to complete authentication-related actions. Examples of authentication-related actions, like authentication a user. Authentication schemes are names that are used to uniquely identify an authentication handler and its configuration options. Authentication handlers are responsible for implementing the strategies for authentication and generating a user's claims given a particular authentication strategy, such as OAuth or OIDC. The configuration options are unique to the strategy as well and provide the handler with configuration that affects authentication behavior, such as redirect URIs.

There are two strategies for determining user access to resources in the authorization layer:

* Role-based strategies determine a user's access based on the role they are assigned, such as `Adminstrator` or `User`. For more information on role-based authorization, review the [role-based authorization documentation](aspnet/core/security/authorization/roles).
* Claim-based strategies determine a user's access based on claims that are issued by identity service.

In ASP.NET, both strategies are captured into an authorization requirement. These requirements are in turn captured into an authorization policy. An authorization policy is uniquely identified with a policy name and captures authorization requriements, which can in turn be role-based or claim-based. The authorization service leverages authorization handlers to determine whether a particular user fulfills the requirements outlined in the authorization policy. Because authorization specifies resource access, it is often necessary to describe what particular endpoints in an application require authorization and what authorization requirements are associated with it.

Enabling authentication and authorization in an ASP.NET application typically requires the following:

- Determining what authentication strategies will be used in an application (OAuth, OIDC, etc.)
- Providing configuration options for the selected authentication strategies
- 

## Enabling authentication in minimal applications

To enable authentication in an application, invoke the `AddAuthentication` method to register the required authentication services on the application's service provider.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication();

var app = builder.Build();

app.Run();
```

Typically, a specifically authentication strategy will be used. In the code sample below, the application is configured with support for cookie-based authentication.

```csharp
using Microsoft.AspNetCore.Authentication.Cookie;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication().AddCookie();

var app = builder.Build();

app.Run();
```

In the code sample below, the application is configured with support for JWT-based authentication.

```csharp
using Microsoft.AspNetCore.Authentication.Cookie;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication().AddJwtBearer();

var app = builder.Build();

app.Run();
```

By default, the WebApplication will automatically register the authentication and authorization middlewares if certain authentication and authorization services are enabled. In the code sample below, it is not necessary to invoke `UseAuthentication` or `UseAuthorization` to register the middlewares since `WebApplication` does this automatically after services are added.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();

var app = builder.Build();

app.Run();
```

However, if it is necessary to manually register authentication and authorization, as in the case of controlling middleware order, then it is possible to do so. In the code sample below, the authentication middleware will run _after_ the CORS middleware has run.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();

var app = builder.Build();

app.Run();
```

### Configuring authentication strategy

Authentication strategies typically support a variety of configurations that are loaded in via options. Minimal application support loading options from configuration for the following authentication strategies:

- JWT bearer-based authentication strategies
- OpenID Connection-based authentication strategies

The ASP.NET framework expects to find these options under the `Authentication:Schemes:{SchemeName}` section in configuration. The `appsettings.json` definition below defines two different schemes, `Bearer` and `LocalAuthIssuer`, with their respective options. The `Authentication:DefaultScheme` option can be used to configure the default authentication strategy that will be used.

```json
{
  "Authentication": {
    "DefaultScheme":  "LocalAuthIssuer",
    "Schemes": {
      "Bearer": {
        "ValidAudiences": [
          "https://localhost:7259",
          "http://localhost:5259"
        ],
        "ValidIssuer": "dotnet-user-jwts"
      },
      "LocalAuthIssuer": {
        "ValidAudiences": [
          "https://localhost:7259",
          "http://localhost:5259"
        ],
        "ValidIssuer": "local-auth"
      }
    }
  }
}
```

In `Program.cs`, we register two JWT bearer-based authentication strategies: one with the default scheme name ("Bearer") and one with the "LocalAuthIssuer" scheme name. 

####  A segue into authentication schemes

Authentication schemes The scheme name is used to uniquely identify an authentication strategy and is used as the lookup key when resolving authentication options from config.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
  .AddJwtBearer()
  .AddJwtBearer("LocalAuthIssuer");
  
var app = builder.Build();

app.Run();
```



## Configuring authorization policies in minimal applications

While authentication is used to identify and validate the identity of users against an API, authorization is used to validate and verify access to resources in an API. 

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthorization();

var app = builder.Build();

app.Run();
```

## Using `dotnet user-jwts` to improve development time testing