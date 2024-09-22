using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace _2FAWithIdentity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {
        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> RegisterAsync(string email, string password)
        {
            await userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            }, password);

            await userManager.SetTwoFactorEnabledAsync(await GetUserAsync(email), true);
            return Ok("Account created");
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> LoginAsync(string email, string password)
        {
            var user = await GetUserAsync(email);
            if (!(await userManager.CheckPasswordAsync(user, password)))
            {
                return Unauthorized();
            }

            var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            return Ok(SendEmail(user, token));
        }

        private object? SendEmail(IdentityUser user, string code)
        {
            StringBuilder emailMessage = new StringBuilder();
            emailMessage.AppendLine("<html>");
            emailMessage.AppendLine("<body>");
            emailMessage.AppendLine($"<p>Dear {user.Email},</p>");
            emailMessage.AppendLine("<p>Thank you for registering with us. To verify your email app</p>");
            emailMessage.AppendLine($"<h2>Verification code: {code}</h2>");
            emailMessage.AppendLine("<p>Please enter this code on our website</p>");
            emailMessage.AppendLine("</body>");
            emailMessage.AppendLine("</html>");

            string message = emailMessage.ToString();
            var email = new MimeMessage();
            email.To.Add(MailboxAddress.Parse("princess.rogahn68@ethereal.email"));
            email.From.Add(MailboxAddress.Parse("princess.rogahn68@ethereal.email"));
            email.Subject = "2FA Verification";
            email.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message };

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("princess.rogahn68@ethereal.email", "dS6NWcVjB4Z5VGAR3j");
            smtp.Send(email);
            smtp.Disconnect(true);
            return "2FA verefication code sent to your email";
        }

        [HttpPost("verify2FA/{email}/{code}")]
        public async Task<IActionResult> Verify2FAAsync(string email, string code)
        {
            var user = await GetUserAsync(email);
            await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultProvider, code);
            return Ok(new[] { "Login successfully", GenerateToken(user) });
        }

        private string GenerateToken(IdentityUser user)
        {
            byte[] key = Encoding.ASCII.GetBytes("Qw12ER34TY56Ui78oi98v2bNh78JK4Hods7uUj12");
            var secureKey = new SymmetricSecurityKey(key);
            var credential = new SigningCredentials(secureKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email!)
            };

            var token = new JwtSecurityToken(
                issuer: null, audience: null, claims: claims, expires: null, signingCredentials: credential);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task<IdentityUser?> GetUserAsync(string email)
        {
            return await userManager.FindByEmailAsync(email);
        }
    }
}
