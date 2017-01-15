#load "..\Services\JwtService.csx"
#load "..\Entities\AuthEntity.csx"
#load "..\Services\AuthService.csx"

#r "..\Common\PppPool.Common.dll"
#r "..\Common\Microsoft.WindowsAzure.Storage.dll"
#r "System.Xml.Linq"
#r "Newtonsoft.Json"

using System;
using System.Xml.Linq;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using System.Net;
using System.Net.Http;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;
using PppPool.Common;

// key(email, userId, name, roles, all), value=query parameter
public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    var jwt = await InlineAuthorize(req, "admin");
    if (jwt == null)
        return req.CreateError(HttpStatusCode.Unauthorized);

    var connectionString = "AuthStorage".GetEnvVar();
    var tableService = new TableService(connectionString);

    IDictionary<string, string> query = req.GetQueryNameValuePairs().ToDictionary(pair => pair.Key, pair => pair.Value);

    var key = query["key"].ToLower();
    var value = string.Empty;
    if (key != "all")
        value = query["value"].ToLower();

    if(key == "email")
    {
        AuthEntity auth = await tableService.GetEntityAsync<AuthEntity>("auth", value, "auth");
        return req.CreateOk(new Jwt(auth.PartitionKey, auth.UserId, auth.Roles, auth.AuthToken, auth.Name));
    }

    if(key == "userid")
    {
        AuthEntity auth = (await tableService.GetEntitiesAsync<AuthEntity>("auth")).FirstOrDefault(x => x.UserId.Equals(value, StringComparison.OrdinalIgnoreCase));
        return req.CreateOk(new Jwt(auth.PartitionKey, auth.UserId, auth.Roles, auth.AuthToken, auth.Name));
    }

    if(key == "name")
    {
        AuthEntity auth = (await tableService.GetEntitiesAsync<AuthEntity>("auth")).FirstOrDefault(x => x.Name.Equals(value, StringComparison.OrdinalIgnoreCase));
        return req.CreateOk(new Jwt(auth.PartitionKey, auth.UserId, auth.Roles, auth.AuthToken, auth.Name));
    }

    if(key == "roles")
    {
        List<AuthEntity> auths = new List<AuthEntity>();
        var roles = value.Split(new[] { ',' });
        foreach (var role in roles)
        {
            auths.AddRange((await tableService.GetEntitiesAsync<AuthEntity>("auth")).Where(x => x.Roles.ToLower().Contains(role)));
        }
        // this will return auths with distinct by partition key (email).
        return req.CreateOk(auths.GroupBy(x => x.PartitionKey).Select(y => y.First()).Select(auth => new Jwt(auth.PartitionKey, auth.UserId, auth.Roles, auth.AuthToken, auth.Name)));
    }

    if(key == "all")
    {
        var auths = await tableService.GetEntitiesAsync<AuthEntity>("auth");
        return req.CreateOk(auths.Select(auth => new Jwt(auth.PartitionKey, auth.UserId, auth.Roles, auth.AuthToken, auth.Name)));
    }

    return req.CreateError(HttpStatusCode.BadRequest);
}

public static async Task<Jwt> InlineAuthorize(HttpRequestMessage req, string role)
{
    if (req.Headers.Authorization == null)
        return null;
    if (req.Headers.Authorization.Scheme != "Bearer")
        return null;

    var authToken = req.Headers.Authorization.Parameter;

    if (string.IsNullOrEmpty(role) || string.IsNullOrEmpty(authToken))
        return null;

    AuthService authService = GetAuthService();

    var authEntity = await authService.AuthenticateAsync(authToken, role);

    return authEntity == null
        ? null
        : new Jwt(authEntity.PartitionKey, authEntity.UserId, authEntity.Roles, authEntity.AuthToken, authEntity.Name);
}