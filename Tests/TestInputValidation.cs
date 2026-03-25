using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using securityMicrosoftCourse.Data;
using securityMicrosoftCourse.Helpers;
using securityMicrosoftCourse.Services;

namespace Tests;

[TestFixture]
public class TestInputValidation {
    private AppDbContext _context = null!;
    private AuthService _authService = null!;
    private const string ValidPassword = "P@ssw0rd!";

    [OneTimeSetUp]
    public void OneTimeSetup()
    {
        // InMemory database for isolated tests
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDB")
            .Options;

        _context = new AppDbContext(options);
        _authService = new AuthService(_context);

        // Seed a valid user
        _context.Users.Add(new IdentityUser
        {
            UserName = "alice",
            Email = "alice@example.com",
            PasswordHash = PasswordHashHelper.HashPassword(ValidPassword)
        });
        _context.SaveChanges();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _context.Dispose();
    }

    [Test]
    public async Task Login_WithValidCredentials_ShouldPass()
    {
        Assert.That(await _authService.LoginUser("alice", ValidPassword), Is.True);
    }

    [Test]
    public async Task Login_WithWrongUsername_ShouldFail()
    {
        Assert.That(await _authService.LoginUser("bob", ValidPassword), Is.False);
    }

    [Test]
    public async Task Login_WithWrongPassword_ShouldFail()
    {
        Assert.That(await _authService.LoginUser("alice", "wrongpassword!"), Is.False);
    }

    [Test]
    public async Task Login_WithSQLInjection_ShouldFail()
    {
        string maliciousUsername = "alice'; DROP TABLE Users; --";
        Assert.That(await _authService.LoginUser(maliciousUsername, ValidPassword), Is.False);
    }

    [Test]
    public async Task Login_WithXSSAttempt_ShouldFail()
    {
        string maliciousUsername = "<script>alert('XSS');</script>";
        Assert.That(await _authService.LoginUser(maliciousUsername, ValidPassword), Is.False);
    }
}