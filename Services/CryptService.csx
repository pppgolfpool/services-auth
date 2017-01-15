#r "..\assemblies\Microsoft.IdentityModel.Tokens.dll"
#r "..\assemblies\Microsoft.AspNetCore.Cryptography.KeyDerivation.dll"

using System;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

public class CryptService
{
    private readonly string _encryptionKey;

    public CryptService(string encryptionKey)
    {
        _encryptionKey = encryptionKey;
    }

    public string Hash(string input, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);
        var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: input,
            salt: saltBytes,
            prf: KeyDerivationPrf.HMACSHA1,
            iterationCount: 10000,
            numBytesRequested: 256 / 8));
        return hashed;
    }

    public string Encrypt(string input)
    {
        var a = new HMACSHA256(Encoding.UTF8.GetBytes(_encryptionKey));
        return Base64UrlEncoder.Encode(a.ComputeHash(Encoding.UTF8.GetBytes(input)));
    }

    public string GenerateSalt()
    {
        var salt = new byte[128 / 8];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        return Convert.ToBase64String(salt);
    }
}