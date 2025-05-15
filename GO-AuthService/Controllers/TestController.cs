using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : ControllerBase
    {
        // Et endpoint, som alle autentificerede brugere (User eller Admin) kan tilgå
        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            var userName = User.Identity?.Name ?? "unknown";
            return Ok(new { message = $"You are authorized, {userName}!" });
        }

        // Et endpoint kun for admins - kræver at JWT-tokenet indeholder "role": "Admin"
        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminEndpoint()
        {
            var userName = User.Identity?.Name ?? "unknown admin";
            return Ok(new { message = $"Hello Admin {userName}, you have access to this endpoint." });
        }

        // Et endpoint kun for almindelige users - kræver at JWT-tokenet indeholder "role": "User"
        [Authorize(Roles = "User")]
        [HttpGet("user")]
        public IActionResult UserEndpoint()
        {
            var userName = User.Identity?.Name ?? "unknown user";
            return Ok(new { message = $"Hello User {userName}, you have access to this endpoint." });
        }
    }
}
