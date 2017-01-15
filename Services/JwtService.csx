#r "..\assemblies\Microsoft.IdentityModel.Tokens.dll"

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Tokens;

public class JwtService
{
    private readonly CryptService _cryptService;

    public JwtService(CryptService cryptService)
    {
        _cryptService = cryptService;
    }

    public string EncodeJwt(string email, string roles, string profileId)
    {
        var properties = new Dictionary<string, object>
        {
            ["iat"] = DateTime.UtcNow,
            ["email"] = email,
            ["roles"] = roles.Split(','),
            ["profileId"] = profileId,
        };
        return EncodeJwt(properties);
    }

    public string EncodeJwt(IDictionary<string, object> properties)
    {
        var header = GetJwtHeader();
        var payload = GetJwtPayload(properties);
        var signature = GetSignature(header, payload);
        return $"{header}.{payload}.{signature}";
    }

    public IDictionary<string, object> DecodeJwt(string jwt)
    {
        var split = jwt.Split('.');
        if (split.Length != 3)
            return null;
        var header = split[0];
        var payload = split[1];
        var recievedSignature = split[2];

        var expectedSignature = GetSignature(header, payload);
        if (recievedSignature != expectedSignature)
            return null;
        var decodedPayload = Base64UrlEncoder.Decode(payload);
        var jObject = JObject.Parse(decodedPayload);
        return jObject.ToObject<IDictionary<string, object>>();
    }

    private static string GetJwtHeader()
    {
        var json = JObject.FromObject(new
        {
            alg = "HS256",
            typ = "JWT",
        });
        return Base64UrlEncoder.Encode(json.ToString(Formatting.Indented));
    }

    private static string GetJwtPayload(IDictionary<string, object> properties)
    {
        var json = JObject.FromObject(properties);
        return Base64UrlEncoder.Encode(json.ToString(Formatting.Indented));
    }

    private string GetSignature(string encodedHeader, string encodedPayload)
    {
        return _cryptService.Encrypt($"{encodedHeader}.{encodedPayload}");
    }
}
// Base64UrlEncoder.Encode(str);