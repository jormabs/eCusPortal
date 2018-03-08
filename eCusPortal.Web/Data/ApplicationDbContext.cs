using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using eCusPortal.Web.Models;

namespace eCusPortal.Web.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            foreach (var entity in modelBuilder.Model.GetEntityTypes())
            {
                if (!entity.Name.StartsWith("AspNet"))
                {
                    // modify column names
                    foreach (var property in entity.GetProperties())
                    {
                        var name = property.Relational().ColumnName;
                        property.Relational().ColumnName = char.ToLower(name[0]) + name.Substring(1);
                    }
                }
            }
        }
    }
}
