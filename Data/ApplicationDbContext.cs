using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using MyMvcAuthApp.Models;

namespace MyMvcAuthApp.Data;

public class ApplicationDbContext : IdentityDbContext
{
    public DbSet<Blog> Blogs { get; set; }
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
}
