using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;

BsonSerializer.RegisterSerializer(new GuidSerializer(MongoDB.Bson.GuidRepresentation.Standard));

// Async Vault secret loader med retry
async Task<Dictionary<string, string>> LoadVaultSecretsAsync()
{
    var retryCount = 0;
    while (true)
    {
        try
        {
            var vaultAddress = Environment.GetEnvironmentVariable("VAULT_ADDR") ?? "http://vault:8200";
            var vaultToken = Environment.GetEnvironmentVariable("VAULT_TOKEN") ?? "wopwopwop123";

            Console.WriteLine($"Henter secrets fra Vault på {vaultAddress} med token...");

            var vaultClientSettings = new VaultClientSettings(vaultAddress, new TokenAuthMethodInfo(vaultToken));
            var vaultClient = new VaultClient(vaultClientSettings);

            var secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(
                path: "go-authservice",
                mountPoint: "secret"
            );

            Console.WriteLine("Secrets hentet fra Vault!");

            return secret.Data.Data.ToDictionary(
                kv => kv.Key,
                kv => kv.Value?.ToString() ?? ""
            );
        }
        catch (Exception ex)
        {
            retryCount++;
            if (retryCount > 5)
            {
                Console.WriteLine($"Fejl ved indlæsning af Vault secrets efter 5 forsøg: {ex.Message}");
                throw;
            }
            Console.WriteLine($"Vault ikke klar endnu, prøver igen om 3 sek... ({retryCount}/5): {ex.Message}");
            await Task.Delay(3000);
        }
    }
}

// Start async main
var builder = WebApplication.CreateBuilder(args);

// Indlæs secrets fra Vault
var vaultSecrets = await LoadVaultSecretsAsync();
builder.Configuration.AddInMemoryCollection(vaultSecrets);

// Logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// Debug Vault secrets
Console.WriteLine("=== Loaded Vault secrets ===");
foreach (var kv in vaultSecrets)
{
    Console.WriteLine($"{kv.Key} = {kv.Value}");
}

// JWT settings
var secretKey = builder.Configuration["Jwt__Secret"];
if (string.IsNullOrWhiteSpace(secretKey))
{
    throw new Exception("JWT Secret key is missing!");
}
Console.WriteLine($"Jwt__Secret læst fra Vault: '{secretKey}' (Length: {secretKey.Length})");

var issuer = builder.Configuration["Jwt__Issuer"];
var audience = builder.Configuration["Jwt__Audience"];

// Hent UserService MongoDB connection string fra Vault (samme som i UserService)
var userMongoConnectionString = builder.Configuration["Mongo__UserServiceConnectionString"];

// Register MongoClient for AuthService (bruger samme connection string som UserService)
builder.Services.AddSingleton<IMongoClient>(_ =>
{
    if (string.IsNullOrWhiteSpace(userMongoConnectionString))
    {
        throw new Exception("MongoDB connection string for UserService mangler fra Vault!");
    }
    return new MongoClient(userMongoConnectionString);
});

// JWT Authentication setup
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = issuer,
        ValidAudience = audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
    };
});

// Authorization policies (hvis relevant for AuthService)
builder.Services.AddAuthorization(options =>
{
    // Tilføj eventuelle autorisationspolitikker her
});

// CORS configuration
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder.WithOrigins("http://localhost:8080") // Tillad din frontend på denne port
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

// Controllers and Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(); // Aktiver CORS middleware - vigtigt at den kommer før Authentication og Authorization

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Vault secrets til test

//igennem vault cli

//docker exec -it vault sh

//export VAULT_ADDR=http://127.0.0.1:8200

//vault login wopwopwop123

//vault kv put secret/go-authservice Jwt__Audience="http://localhost" Jwt__Issuer="GO.AuthService" Jwt__Secret="din-hemmelige - nøgle - 32 - tegn - hej - med - dig - type - shi" Mongo__UserServiceConnectionString="mongodb + srv://micromaend:micromaend@go-userservicedb.utyowom.mongodb.net /? retryWrites = true & w = majority & appName = GO - UserServiceDB"