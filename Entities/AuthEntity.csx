#r "Microsoft.WindowsAzure.Storage"

using System;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;

public class AuthEntity : TableEntity
{
    public AuthEntity()
    {

    }

    public AuthEntity(string partitionKey)
    {
        RowKey = "auth";
        PartitionKey = partitionKey;
    }

    public string AuthToken { get; set; }
    public bool Change { get; set; }
    public string ChangeCode { get; set; }
    public DateTime ChangeExpiry { get; set; }
    public DateTime Expires { get; set; }
    public string Password { get; set; }
    public string Salt { get; set; }
    public string Roles { get; set; }
    public string UserId { get; set; }
    public string Name { get; set; }

    public object GetResponseObject()
    {
        return new
        {
            email = PartitionKey,
            authToken = AuthToken,
            authTokenExpires = Expires,
            userId = UserId,
            name = Name ?? string.Empty,
            roles = string.Join(",", Roles)
        };
    }
}