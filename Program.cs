using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using MyMvcAuthApp.Data;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>();
builder.Services.AddControllersWithViews();

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Hatalı giriş denemeleri için ayarlar
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); // 15 dakika süreyle kilitle
    options.Lockout.MaxFailedAccessAttempts = 5; // 5 başarısız denemeden sonra kilitle
    options.Lockout.AllowedForNewUsers = true; // Yeni kullanıcılar için de kilitleme etkin
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
