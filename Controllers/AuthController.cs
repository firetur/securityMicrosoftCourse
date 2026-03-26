using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using securityMicrosoftCourse.Models;
using securityMicrosoftCourse.Services;

namespace securityMicrosoftCourse.Controllers;

public class AuthController : Controller
{
    private readonly AuthService _authService;

    public AuthController(AuthService authService)
    {
        _authService = authService;
    }
    
    [HttpGet]
    public IActionResult Register()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    [HttpPost]
    public IActionResult Register(string username, string email, string password)
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Home");
        }

        if (string.IsNullOrWhiteSpace(username) ||
            string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password))
        {
            ViewBag.Error = "All fields are required.";
            return View();
        }

        bool success = _authService.RegisterUser(username, email, password);

        if (!success)
        {
            // Generic error message to prevent account enumeration attacks
            ViewBag.Error = "Registration failed. Please check your input and try again.";
            return View();
        }

        TempData["Message"] = "Registration successful! You can now log in.";
        return RedirectToAction("Login", "Auth");
    }

    [HttpGet]
    public IActionResult Login()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            return RedirectToAction("Index", "Home");
        }

        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            ViewBag.Error = "Both username and password are required.";
            return View();
        }

        bool success = await _authService.LoginUser(username, password);

        if (!success)
        {
            ViewBag.Error = "Invalid username or password.";
            return View();
        }

        return RedirectToAction("Index", "Home");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _authService.SignOutUserAsync();
        return RedirectToAction("Login", "Auth");
    }

    [HttpGet]
    public IActionResult AccessDenied()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
