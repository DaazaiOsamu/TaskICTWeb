using Microsoft.EntityFrameworkCore;

namespace TaskICTWeb.Models
{
    public class DB : DbContext
    {
        public DB(DbContextOptions<DB> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}