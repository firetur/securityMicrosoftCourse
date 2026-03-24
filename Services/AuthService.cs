using securityMicrosoftCourse.Data;
using securityMicrosoftCourse.Helpers;

namespace securityMicrosoftCourse.Services;

public class AuthService
{
    private readonly AppDbContext _context;

    public AuthService(AppDbContext context)
    {
        _context = context;
    }

    /// <summary>
    /// Authenticates a user with validated inputs.
    /// </summary>
    public bool LoginUser(string username, string password)
    {
        // Validate username and password
        if (!ValidationHelper.IsValidInput(username) ||
            !ValidationHelper.IsValidInput(password, "!@#$%^&*?") ||
            !ValidationHelper.IsValidXssInput(username))
        {
            return false;
        }

       // Find user by username
        var user = _context.Users.SingleOrDefault(u => u.Username == username);
        if (user == null) return false;

        // Compare password hash
        return PasswordHasher.VerifyPassword(password, user.Password);
    }
}