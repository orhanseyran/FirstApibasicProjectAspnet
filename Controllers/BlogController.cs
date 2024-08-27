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
using Microsoft.AspNetCore.RateLimiting;

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
        [EnableRateLimiting("LoginPolicy")]
       public async Task<IActionResult> Login(User user)
{
            // Kullanıcı e-posta ve şifre alanlarının boş olup olmadığını kontrol edin
            if (string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("E-posta ve şifre alanları boş olamaz.");
            }

            // Kullanıcıyı e-posta adresine göre bulun
            var useremail = await _userManager.FindByEmailAsync(user.Email);
            if (useremail == null)
            {
                return NotFound("Kullanıcı bulunamadı.");
            }

            // Hesap kilitli mi kontrol et
            if (await _userManager.IsLockedOutAsync(useremail))
            {
                return Unauthorized("Birden Fazla Hatalı Giriş Yaptınız. Hesabınız 15 dakika boyunca kilitlenecektir.");
            }

            // E-posta doğrulaması kontrolü (isteğe bağlı)
            if (!useremail.EmailConfirmed)
            {
                return Unauthorized("E-posta adresiniz henüz doğrulanmadı. Lütfen e-posta adresinizi doğrulayın.");
            }

            // Şifre doğrulama işlemi
            var result = await _signInManager.PasswordSignInAsync(useremail.UserName, user.Password, false, true); // LockoutOnFailure: true
            if (result.Succeeded)
            {
                // Kilitleme sayacını sıfırla (başarılı giriş)
                await _userManager.ResetAccessFailedCountAsync(useremail);

                // JWT token oluşturma
                var token = GenerateJwtToken(useremail);

                return Ok(new
                {
                    message = "Login Successful",
                    user = new { useremail.UserName, useremail.Email },
                    token = token
                });
            }
            else if (result.IsLockedOut)
            {
                return Unauthorized("Birden Fazla Hatalı Giriş Yaptınız. Hesabınız 15 dakika boyunca kilitlenecektir.");
            }
            else
            {
                // Başarısız giriş sayısını artır
                await _userManager.AccessFailedAsync(useremail);
                return Unauthorized("Hatalı şifre girdiniz. Lütfen tekrar deneyin.");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Register(User user)
        {
            // Kullanıcı e-posta ve şifre alanlarının boş olup olmadığını kontrol edin
            if (string.IsNullOrEmpty(user.Email) || string.IsNullOrEmpty(user.Password))
            {
                return BadRequest("E-posta ve şifre alanları boş olamaz.");
            }

            // Kullanıcıyı e-posta adresine göre arayın
            var useremail = await _userManager.FindByEmailAsync(user.Email);
            if (useremail != null)
            {
                return BadRequest("Bu e-posta adresi zaten kullanılıyor.");
            }

            // Yeni kullanıcı oluşturma
            var newUser = new IdentityUser { UserName = user.Email, Email = user.Email };
            var result = await _userManager.CreateAsync(newUser, user.Password);
            if (result.Succeeded)
            {
                // Kullanıcı başarıyla kaydedildi
                return Ok("Kullanıcı başarıyla kaydedildi.");
            }

            return BadRequest(result.Errors);
        }

        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtKey = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(jwtKey) || jwtKey.Length < 32) // 32 karakter = 256 bit
            {
                throw new InvalidOperationException("JWT Key configuration is missing or too short. The key must be at least 256 bits (32 characters).");
            }

            // Claim'ler oluşturuluyor
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Benzersiz kimlik
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()), // Token oluşturulma zamanı
                // Gerekirse diğer gerekli claim'ler
            };

            // Güvenlik anahtarı ve imza bilgileri
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // JWT Token oluşturma
            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30), // Kısa süreli token
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