using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using MongoDB.Driver;
using GOCore;

[Route("auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IMongoCollection<User> _users;
    private readonly IMongoCollection<Admin> _admins;
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config, IMongoClient mongoClient)
    {
        _config = config;
        var mongoSection = config.GetSection("Mongo");

        var userDbName = mongoSection["UserDatabase"];
        var userCollection = mongoSection["UsersCollection"];
        var adminCollection = mongoSection["AdminsCollection"];

        Console.WriteLine($"Jwt__Secret i AuthController: '{_config["Jwt__Secret"]}' (Length: {_config["Jwt__Secret"]?.Length ?? 0})");
        Console.WriteLine($"Jwt__Issuer i AuthController: '{_config["Jwt__Issuer"]}'");
        Console.WriteLine($"Jwt__Audience i AuthController: '{_config["Jwt__Audience"]}'");
        Console.WriteLine($"Mongo__ConnectionString i AuthController: '{_config["Mongo__ConnectionString"]}'");

        var Db = mongoClient.GetDatabase(userDbName);

        _users = Db.GetCollection<User>(userCollection);
        _admins = Db.GetCollection<Admin>(adminCollection);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        Console.WriteLine($"Login attempt for UserName: {request.UserName}");

        // Tjek først i Admin collection
        var admin = await _admins.Find(a => a.UserName == request.UserName).FirstOrDefaultAsync();
        if (admin != null)
        {
            Console.WriteLine($"Admin found: {admin.UserName}");

            if (request.Password?.Trim() == admin.Password?.Trim())
            {
                Console.WriteLine("Admin password match.");
                var token = GenerateJwtToken(admin, "Admin");
                return Ok(new { token });
            }
            else
            {
                Console.WriteLine($"Admin password mismatch. Expected: {admin.Password}, Got: {request.Password}");
                return Unauthorized(new { message = "Invalid username or password" });
            }
        }
        else
        {
            Console.WriteLine("No admin found with that username.");
        }

        // Hvis ikke admin, tjek i User collection
        var user = await _users.Find(u => u.UserName == request.UserName).FirstOrDefaultAsync();
        if (user != null)
        {
            Console.WriteLine($"User found: {user.UserName}");

            if (request.Password?.Trim() == user.Password?.Trim())
            {
                Console.WriteLine("User password match.");
                var token = GenerateJwtToken(user, "User");
                return Ok(new { token });
            }
            else
            {
                Console.WriteLine($"User password mismatch. Expected: {user.Password}, Got: {request.Password}");
                return Unauthorized(new { message = "Invalid username or password" });
            }
        }

        Console.WriteLine("No user found with that username.");
        return Unauthorized(new { message = "Invalid username or password" });
    }


    private string GenerateJwtToken(object identityObject, string role)
    {
        // Hent Id og UserName dynamisk, da Admin og User ikke har fælles interface
        string id = "";
        string userName = "";

        switch (identityObject)
        {
            case Admin admin:
                id = admin.Id.ToString();
                userName = admin.UserName;
                break;
            case User user:
                id = user.Id.ToString();
                userName = user.UserName;
                break;
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, id),
            new Claim(ClaimTypes.Name, userName),
            new Claim(ClaimTypes.Role, role)
        };

        // Hent JWT secret direkte fra _config her med det korrekte navn fra Vault
        var secretKey = _config["Jwt__Secret"];
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["Jwt__Issuer"], // Brug det korrekte navn fra Vault
            audience: _config["Jwt__Audience"], // Brug det korrekte navn fra Vault
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public class LoginRequest
{
    public string UserName { get; set; }
    public string Password { get; set; }
}