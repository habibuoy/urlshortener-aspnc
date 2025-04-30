using Microsoft.EntityFrameworkCore;
using UrlShortener.Model;

namespace UrlShortener.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }

    public DbSet<UrlEnt> Urls { get; set; }
}