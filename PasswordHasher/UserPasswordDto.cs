namespace PasswordHasher
{
    public class UserPasswordDto
    {
        public long Id { get; set; }
        public string Password { get; set; }
        public string CurrentPassword { get; set; }
    }
}
