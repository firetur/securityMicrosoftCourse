using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using securityMicrosoftCourse.Data;
using securityMicrosoftCourse.Helpers;

namespace securityMicrosoftCourse.Services;

public class AuthService
{
    private readonly AppDbContext _context;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public AuthService(AppDbContext context)
        : this(context, null)
    {
    }

    public AuthService(AppDbContext context, IHttpContextAccessor? httpContextAccessor)
    {
        _context = context;
        _httpContextAccessor = httpContextAccessor;
    }

    public bool RegisterUser(string username, string email, string password)
    {
        if (!HasValidCredentialsInput(username, password))
        {
            return false;
        }

        // Validate email format
        if (!ValidationHelper.IsValidEmail(email))
        {
            return false;
        }

        if (FindUserByUsername(username) is not null)
            return false;

        var roleName = _context.Users.Any() ? "User" : "Admin";
        var identityRole = EnsureRoleExists(roleName);
        
        var user = new IdentityUser
        {
            UserName = username,
            Email = email,
            PasswordHash = PasswordHashHelper.HashPassword(password)
        };

        _context.Users.Add(user);
        _context.SaveChanges();

        _context.UserRoles.Add(new IdentityUserRole<string>
        {
            UserId = user.Id,
            RoleId = identityRole.Id
        });
        _context.SaveChanges();

        return true;
    }

    public async Task<bool> LoginUser(string username, string password)
    {
        if (!HasValidCredentialsInput(username, password))
        {
            return false;
        }

        var user = FindUserByUsername(username);
        if (user == null) return false;

        if (string.IsNullOrWhiteSpace(user.PasswordHash))
            return false;

        if (!PasswordHashHelper.VerifyPassword(password, user.PasswordHash))
            return false;

        var httpContext = _httpContextAccessor?.HttpContext;
        if (httpContext == null)
            return true;

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, username)
        };

        var userRoles = FindRoleNamesByUserId(user.Id);
        foreach (var roleName in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, roleName));
        }

        var identity = new ClaimsIdentity(claims, IdentityConstants.ApplicationScheme);
        var principal = new ClaimsPrincipal(identity);

        await httpContext.SignInAsync(
            IdentityConstants.ApplicationScheme,
            principal,
            new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30)
            });

        return true;
    }

    public async Task SignOutUserAsync()
    {
        var httpContext = _httpContextAccessor?.HttpContext;
        if (httpContext == null)
            return;

        await httpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
    }

    private static bool HasValidCredentialsInput(string username, string password)
    {
        return ValidationHelper.IsValidInput(username) &&
               ValidationHelper.IsValidInput(password, "!@#$%^&*?") &&
               ValidationHelper.IsValidXssInput(username);
    }

    private IdentityUser? FindUserByUsername(string username)
    {
        return _context.Users.SingleOrDefault(u => u.UserName == username);
    }

    private IEnumerable<string> FindRoleNamesByUserId(string userId)
    {
        return from userRole in _context.UserRoles
               join role in _context.Roles on userRole.RoleId equals role.Id
               where userRole.UserId == userId && role.Name != null
               select role.Name;
    }

    private IdentityRole EnsureRoleExists(string roleName)
    {
        var role = _context.Roles.SingleOrDefault(r => r.Name == roleName);
        if (role != null)
            return role;

        role = new IdentityRole(roleName);
        _context.Roles.Add(role);
        _context.SaveChanges();
        return role;
    }
}