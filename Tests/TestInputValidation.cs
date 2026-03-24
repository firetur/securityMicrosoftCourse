using Microsoft.EntityFrameworkCore;
using securityMicrosoftCourse.Data;
using securityMicrosoftCourse.Helpers;
using securityMicrosoftCourse.Models;
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
        _context.Users.Add(new User
        {
            Username = "alice",
            Email = "alice@example.com",
            Password = PasswordHasher.HashPassword(ValidPassword)
        });
        _context.SaveChanges();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _context.Dispose();
    }

    [Test]
    public void Login_WithValidCredentials_ShouldPass()
    {
        Assert.That(_authService.LoginUser("alice", ValidPassword), Is.True);
    }

    [Test]
    public void Login_WithWrongUsername_ShouldFail()
    {
        Assert.That(_authService.LoginUser("bob", ValidPassword), Is.False);
    }

    [Test]
    public void Login_WithWrongPassword_ShouldFail()
    {
        Assert.That(_authService.LoginUser("alice", "wrongpassword!"), Is.False);
    }

    [Test]
    public void Login_WithSQLInjection_ShouldFail()
    {
        string maliciousUsername = "alice'; DROP TABLE Users; --";
        Assert.That(_authService.LoginUser(maliciousUsername, ValidPassword), Is.False);
    }

    [Test]
    public void Login_WithXSSAttempt_ShouldFail()
    {
        string maliciousUsername = "<script>alert('XSS');</script>";
        Assert.That(_authService.LoginUser(maliciousUsername, ValidPassword), Is.False);
    }
}