using System.Text.RegularExpressions;

namespace securityMicrosoftCourse.Helpers;

public static class ValidationHelper
{
    // Comprehensive XSS pattern detection
    private static readonly string[] XssPatterns = new[]
    {
        @"<\s*script", @"javascript:", @"on\w+\s*=", // Event handlers
        @"<\s*iframe", @"<\s*object", @"<\s*embed", @"<\s*applet",
        @"<\s*link", @"<\s*meta", @"<\s*style",
        @"<\s*img\s+[^>]*onerror", @"<\s*svg\s+[^>]*onload", // XSS via onerror/onload
        @"vbscript:", @"data:text/html", // Protocol-based XSS
        @"<\s*body\s+[^>]*onload" // Body onload
    };

    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrEmpty(input))
            return false;

        // Basic length check to prevent buffer overflow
        if (input.Length > 255)
            return false;

        var validCharacters = allowedSpecialCharacters.ToHashSet();
        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }

    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
            return false;

        // RFC 5322 simplified email validation
        var emailPattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
        if (!Regex.IsMatch(email, emailPattern))
            return false;

        // Additional checks
        if (email.Length > 254) // RFC 5321
            return false;

        var parts = email.Split('@');
        if (parts[0].Length > 64) // Local part max length
            return false;

        // Check for XSS patterns in email
        if (!IsValidXssInput(email))
            return false;

        return true;
    }

    public static bool IsValidXssInput(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return true;

        var lower = input.ToLowerInvariant();

        // Check for common XSS tags and patterns
        foreach (var pattern in XssPatterns)
        {
            if (Regex.IsMatch(lower, pattern, RegexOptions.IgnoreCase))
                return false;
        }

        // Check for HTML entities that could be decoded to malicious content
        if (lower.Contains("&#") || lower.Contains("&lt;") || lower.Contains("&gt;"))
        {
            var decoded = System.Net.WebUtility.HtmlDecode(input);
            if (decoded != input && !IsValidXssInput(decoded))
                return false;
        }

        return true;
    }
}