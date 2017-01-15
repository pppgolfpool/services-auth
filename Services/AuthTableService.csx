#load "..\Entities\AuthEntity.csx"
#r "..\Common\Microsoft.WindowsAzure.Storage.dll"

using System.Threading.Tasks;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;

public class AuthTableService
{
    private const string AuthRowKey = "auth";
    private readonly CloudTable _table;

    public AuthTableService(string connectionString, string usersTableName)
    {
        var storageAccount = CloudStorageAccount.Parse(connectionString);
        var tableClient = storageAccount.CreateCloudTableClient();
        _table = tableClient.GetTableReference(usersTableName);
    }

    public async Task<AuthEntity> RetrieveAsync(string userId)
    {
        var operation = TableOperation.Retrieve<AuthEntity>(userId, AuthRowKey);
        var authEntity = (AuthEntity)(await _table.ExecuteAsync(operation)).Result;
        return authEntity;
    }

    public async Task UpsertAsync(AuthEntity authEntity)
    {
        var insertOrReplaceOp = TableOperation.InsertOrReplace(authEntity);
        await _table.ExecuteAsync(insertOrReplaceOp);
    }
}