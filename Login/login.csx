﻿#load "..\Services\CryptService.csx"
#load "..\Services\JwtService.csx"
#load "..\Services\AuthTableService.csx"
#load "..\Services\AuthService.csx"
#load "..\Entities\AuthEntity.csx"

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

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    IDictionary<string, string> query = req.GetQueryNameValuePairs().ToDictionary(pair => pair.Key, pair => pair.Value);

    var userId = query["userId"];
    var password = query["password"];
    if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(password))
        return req.CreateError(HttpStatusCode.Unauthorized);

    AuthService authService = GetAuthService();

    var authEntity = await authService.LoginAsync(userId, password);

    return authEntity == null
        ? req.CreateError(HttpStatusCode.Unauthorized)
        : req.CreateOk(authEntity.GetResponseObject());
}