using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MyMvcAuthApp.Data;
using MyMvcAuthApp.Models;

using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

using System.Text;
using System.Threading.Tasks;
using System;

namespace Namespace
{
    public class BlogController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ApplicationDbContext _db;
        private readonly IConfiguration _configuration;

        public BlogController(ApplicationDbContext db, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _db = db;
            _signInManager = signInManager;
            _configuration = configuration;
        }
        [HttpPost]
        public async Task<IActionResult> Login(User user)
        {
            // Kullanıcı e-posta ve şifre alanlarının boş olup olmadığını kontrol edin
            if (string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("Email and password are required.");
            }

            // Kullanıcıyı e-posta adresine göre bulun
            var useremail = await _userManager.FindByEmailAsync(user.Email);
            if (useremail == null)
            {
                return NotFound("User not found.");
            }

            // E-posta doğrulaması kontrolü (isteğe bağlı)
            if (!useremail.EmailConfirmed)
            {
                return Unauthorized("Email not confirmed.");
            }

            // Şifre doğrulama işlemi
            var result = await _signInManager.PasswordSignInAsync(useremail.UserName, user.Password, false, false);
            if (result.Succeeded)
            {
                // JWT token oluşturma
                var token = GenerateJwtToken(useremail);

                return Ok(new
                {
                    message = "Login Successful",
                    user = new { useremail.UserName, useremail.Email },
                    token = token
                });
            }

            return Unauthorized("Invalid login attempt. Please check your credentials.");
        }

        [HttpPost]
        public async Task<IActionResult> Register(User user)
        {
            // Kullanıcı e-posta ve şifre alanlarının boş olup olmadığını kontrol edin
            if (string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("Email and password are required.");
            }

            // Kullanıcıyı e-posta adresine göre arayın
            var useremail = await _userManager.FindByEmailAsync(user.Email);
            if (useremail != null)
            {
                return BadRequest("Email already exists.");
            }

            // Yeni kullanıcı oluşturma
            var newUser = new IdentityUser { UserName = user.Email, Email = user.Email };
            var result = await _userManager.CreateAsync(newUser, user.Password);
            if (result.Succeeded)
            {
                // Kullanıcı başarıyla kaydedildi
                return Ok("User registered successfully.");
            }

            return BadRequest(result.Errors);
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            // JWT Key'in null olup olmadığını kontrol edin
            var jwtKey = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(jwtKey))
            {
                throw new InvalidOperationException("JWT Key configuration is missing.");
            }

            // Claim'ler oluşturuluyor
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                // Ek claim'ler ekleyebilirsiniz
            };

            // Güvenlik anahtarı ve imza bilgileri
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // JWT Token oluşturma
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [HttpGet]
        public async Task<IActionResult> Index()
        {
           var blog = await _db.Blogs.ToListAsync();
           if (blog == null)
           {
            return NotFound();
           }
            
            return Ok(blog);
        }

        [HttpGet]
        public async Task<IActionResult> Details(int id)
        {
            var blog = await _db.Blogs.FirstOrDefaultAsync(x=>x.Id == id);
            if (blog == null)
            {
                return NotFound();
                
            }
            return Ok(blog);
        }

        [HttpGet]
        public async Task<IActionResult> Delete(int id)
        {
            var blog = await _db.Blogs.FirstOrDefaultAsync(x=>x.Id == id);
            if (blog == null)
            {
                return NotFound();
            }
            _db.Blogs.Remove(blog);
            await _db.SaveChangesAsync();
            return Ok(blog);
        }

        [HttpPost]
        public async Task<IActionResult> Create(Blog blog)
        {
            if (blog == null)
            {
                return BadRequest();
                
            }
            if (ModelState.IsValid)
            {
                _db.Blogs.Add(blog);
                await _db.SaveChangesAsync();
                return Ok(blog);
                
            }
            return BadRequest();
        }
    }
}