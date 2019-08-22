using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private List<User> _users = new List<User>
        {
            new User { AccountNumber = 1234567, Currency = "AUS", FullName = "Rajesh Khanna", Username = "rajesh", Password = "rajesh@123" },
            new User { AccountNumber = 1239567, Currency = "NPR", FullName = "Ramesh Sharma", Username = "ramesh", Password = "ramesh@123" },
            new User { AccountNumber = 1238567, Currency = "USD", FullName = "Durga Fuyal", Username = "durga", Password = "durga@123" },
        };

        [AllowAnonymous]
        [HttpPost("authentication")]
        public IActionResult Authentication([FromBody] Login loginParam)
        {
            var token = Authenticate(loginParam.Username, loginParam.Password);

            if (token == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return Ok(token);
        }

        public SecurityToken Authenticate(string username, string password)
        {
            var user = _users.SingleOrDefault(x => x.Username == username && x.Password == password);

            // return null if user not found
            if (user == null)
                return null;

            // authentication successful so generate jwt token
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("3ce1637ed40041cd94d4853d3e766c4d");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("accountnumber", user.AccountNumber.ToString()),
                    new Claim("currency", user.Currency),
                    new Claim("name", user.FullName)
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var jwtSecurityToken = tokenHandler.WriteToken(token);

            return new SecurityToken() { auth_token = jwtSecurityToken };
        }

    }
    public class SecurityToken
    {
        public string auth_token { get; set; }
    }
    public class User
    {
        public int AccountNumber { get; set; }
        public string FullName { get; set; }
        public string Currency { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }
    public class Login
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
