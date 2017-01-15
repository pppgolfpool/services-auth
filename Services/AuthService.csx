#load "..\Services\AuthTableService.csx"
#load "..\Services\CryptService.csx"
#load "..\Services\JwtService.csx"
#load "..\Entities\AuthEntity.csx"

#r "..\Common\PppPool.Common.dll"

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using PppPool.Common;

public static AuthService GetAuthService()
{
    var connectionString = "PppPoolStorage".GetEnvVar();
    var authTableService = new AuthTableService(connectionString, "users");

    var jwtSecret = "JwtSecret".GetEnvVar();
    var cryptService = new CryptService(jwtSecret);

    var jwtService = new JwtService(cryptService);

    var authService = new AuthService(authTableService, cryptService, jwtService);
    return authService;
}

public class AuthService
{
    private readonly AuthTableService _authTableService;
    private readonly CryptService _cryptService;
    private readonly JwtService _jwtService;

    public AuthService(
        AuthTableService authTableService,
        CryptService cryptService,
        JwtService jwtService)
    {
        _authTableService = authTableService;
        _cryptService = cryptService;
        _jwtService = jwtService;
    }

    public async Task<AuthEntity> LoginAsync(string userId, string password)
    {
        var authEntity = await _authTableService.RetrieveAsync(userId);

        if (string.IsNullOrEmpty(authEntity?.Password) || string.IsNullOrEmpty(authEntity.Salt))
            return null;

        var storedHash = authEntity.Password;
        var incomingHash = _cryptService.Hash(password, authEntity.Salt);

        if (storedHash != incomingHash)
            return null;

        // if there is already an authtoken, use it.
        var authToken = string.IsNullOrEmpty(authEntity.AuthToken) ? _jwtService.EncodeJwt(authEntity.PartitionKey, authEntity.Roles, authEntity.UserId) : authEntity.AuthToken;

        authEntity.AuthToken = authToken;
        authEntity.Expires = DateTime.UtcNow.AddDays(9999);
        authEntity.Change = false;
        authEntity.ChangeCode = string.Empty;
        authEntity.ChangeExpiry = DateTime.UtcNow;

        await _authTableService.UpsertAsync(authEntity);
        return authEntity;
    }

    public async Task<AuthEntity> AuthenticateAsync(string authToken, string role)
    {
        var serviceToken = "ServiceToken".GetEnvVar();
        if(authToken.Equals(serviceToken, StringComparison.OrdinalIgnoreCase))
            return new AuthEntity()
            {
                AuthToken = serviceToken,
                Roles = "service",
                UserId = "service",
            };

        var authProperties = _jwtService.DecodeJwt(authToken);
        if (authProperties == null)
            return null;

        var email = (string)authProperties["email"];

        var authEntity = await _authTableService.RetrieveAsync(email);

        if (authEntity.Change || !string.IsNullOrEmpty(authEntity.ChangeCode))
            return null;

        if (authEntity.AuthToken != authToken || DateTime.UtcNow > authEntity.Expires)
            return null;

        if (!authEntity.Roles.Split(',').Select(x => x.ToLower()).Contains(role.ToLower()))
            return null;

        return authEntity;
    }

    public async Task<AuthEntity> ChangePasswordAsync(string userId, string changeCode, string newPassword)
    {
        var authEntity = await _authTableService.RetrieveAsync(userId);
        if (!authEntity.Change || authEntity.ChangeCode != changeCode || DateTime.UtcNow > authEntity.ChangeExpiry)
            return null;

        var salt = _cryptService.GenerateSalt();
        var hash = _cryptService.Hash(newPassword, salt);
        authEntity.Salt = salt;
        authEntity.Password = hash;
        authEntity.Change = false;
        authEntity.ChangeCode = string.Empty;
        authEntity.ChangeExpiry = DateTime.UtcNow;

        await _authTableService.UpsertAsync(authEntity);
        return authEntity;
    }

    public async Task<AuthEntity> RequestPasswordChangeAsync(string userId)
    {
        var authEntity = await _authTableService.RetrieveAsync(userId);

        authEntity.Change = true;
        authEntity.ChangeExpiry = DateTime.UtcNow.AddDays(1);
        authEntity.ChangeCode = _jwtService.EncodeJwt(new Dictionary<string, object>
        {
            ["iat"] = DateTime.UtcNow,
            ["email"] = userId,
        });

        await _authTableService.UpsertAsync(authEntity);
        return authEntity;
    }
}