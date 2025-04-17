using System.ComponentModel.DataAnnotations;

namespace TaskICTWeb.Models
{
    public class User
    {
        public int UserID { get; set; }

        [Required]
        [MaxLength(255)]
        public string? UserName { get; set; }
        [Required]

        [MaxLength(100)]
        [EmailAddress]
        public string? Email { get; set; }

        [Required]
        [MaxLength(255)] 
        public string? Password { get; set; }
    }
}