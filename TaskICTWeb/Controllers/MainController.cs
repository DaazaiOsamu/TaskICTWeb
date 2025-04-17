using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TaskICTWeb.Models;

namespace TaskICTWeb.Controllers
{
    public class MainController : Controller
    {
        private readonly DB _openDB;
        private readonly IConfiguration _configuration;

        public MainController(DB openDB, IConfiguration configuration)
        {
            _openDB = openDB;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Authorization()
        {
            return View("~/Views/Account/Authorization.cshtml");
        }

        [HttpPost]
        public async Task<IActionResult> Authorization(string email, string password, string action)
        {
            if (action == "authorization")
            {
                var user = await _openDB.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.Password))
                {
                    ViewBag.Error = "Неверный 'email' или 'пароль'";
                    return View("~/Views/Account/Authorization.cshtml");
                }

                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim("UserId", user.Email.ToString()),
                    new Claim("UserName", user.UserName),
                    new Claim(ClaimTypes.Name, user.UserName)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    audience: _configuration["Jwt:Audience"],
                    claims: claims,
                    expires: DateTime.Now.AddHours(1),
                    signingCredentials: creds);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

                Response.Cookies.Append("jwtToken", tokenString, new CookieOptions
                {
                    HttpOnly = true,
                    Expires = DateTimeOffset.Now.AddHours(1)
                });

                return RedirectToAction("Home", "Main");
            }

            if (action == "registration")
            {
                return RedirectToAction("Registration", "Main");
            }

            return View("~/Views/Account/Authorization.cshtml");
        }

        [HttpGet]
        public IActionResult Registration()
        {
            return View("~/Views/Account/Registration.cshtml");
        }

        [HttpPost]
        public async Task<IActionResult> Registration(User user)
        {
            if (string.IsNullOrWhiteSpace(user.Password))
            {
                ViewBag.Error = "Введите 'пароль'";
                return View("~/Views/Account/Registration.cshtml");
            }

            if (await _openDB.Users.AnyAsync(u => u.Email == user.Email))
            {
                ViewBag.Error = "Пользователь с таким 'email' уже существует";
                return View("~/Views/Account/Registration.cshtml");
            }

            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
            _openDB.Users.Add(user);
            await _openDB.SaveChangesAsync();

            return RedirectToAction("Authorization", "Main");
        }

        [HttpGet]
        public IActionResult PasswordUpdate()
        {
            return View("~/Views/Account/PasswordUpdate.cshtml");
        }

        [HttpPost]
        public async Task<IActionResult> PasswordUpdate(string email, string newPassword)
        {
            var user = await _openDB.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                ViewBag.Error = "Пользователь не найден";
                return View("~/Views/Account/PasswordUpdate.cshtml");
            }

            if (string.IsNullOrWhiteSpace(newPassword))
            {
                ViewBag.Error = "Введите новый 'пароль'";
                return View("~/Views/Account/PasswordUpdate.cshtml");
            }

            user.Password = BCrypt.Net.BCrypt.HashPassword(newPassword);
            await _openDB.SaveChangesAsync();

            return RedirectToAction("Authorization", "Main");
        }

        [HttpGet]
        public IActionResult Home()
        {
            string? userName = User.Identity.Name;
            ViewBag.UserName = userName;
            return View("~/Views/Account/Home.cshtml");
        }
    }
}