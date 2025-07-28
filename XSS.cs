using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using System.Text;

namespace VulnerableApp.Controllers
{
    public class HomeController : Controller
    {
        // VULNERABLE: Reflected XSS - Direct output of user input
        [HttpGet]
        public IActionResult Search(string query)
        {
            if (string.IsNullOrEmpty(query))
            {
                return View();
            }

            // VULNERABLE: Direct insertion of user input into HTML without encoding
            ViewBag.SearchTerm = query;
            ViewBag.Message = $"<p>You searched for: <strong>{query}</strong></p>";
            
            return View();
        }

        // VULNERABLE: XSS through ViewBag/ViewData
        [HttpGet]
        public IActionResult Welcome(string name)
        {
            // VULNERABLE: User input passed directly to view without sanitization
            ViewData["WelcomeMessage"] = $"<h2>Welcome back, {name}!</h2>";
            ViewBag.UserName = name;
            
            return View();
        }

        // VULNERABLE: XSS in JSON response
        [HttpGet]
        public IActionResult GetUserInfo(string userId)
        {
            // VULNERABLE: User input directly embedded in JSON response
            var jsonResponse = $@"{{
                ""userId"": ""{userId}"",
                ""message"": ""<div>User ID: {userId} loaded successfully</div>"",
                ""timestamp"": ""{DateTime.Now}""
            }}";

            return Content(jsonResponse, "application/json");
        }

        // VULNERABLE: XSS through HTML building
        [HttpPost]
        public IActionResult AddComment(string comment, string author)
        {
            // VULNERABLE: Building HTML with unescaped user input
            var htmlBuilder = new StringBuilder();
            htmlBuilder.Append("<div class='comment'>");
            htmlBuilder.Append($"<h4>Comment by: {author}</h4>");
            htmlBuilder.Append($"<p>{comment}</p>");
            htmlBuilder.Append($"<small>Posted on: {DateTime.Now}</small>");
            htmlBuilder.Append("</div>");

            ViewBag.CommentHtml = htmlBuilder.ToString();
            
            return View("Comments");
        }

        // VULNERABLE: XSS in error messages
        [HttpGet]
        public IActionResult ProcessData(string data)
        {
            try
            {
                // Some processing logic here
                if (string.IsNullOrEmpty(data))
                {
                    throw new ArgumentException($"Invalid data received: {data}");
                }
                
                return Ok();
            }
            catch (Exception ex)
            {
                // VULNERABLE: Exception message with user input displayed without encoding
                var errorHtml = $"<div class='error'>Error processing data '{data}': {ex.Message}</div>";
                ViewBag.ErrorMessage = errorHtml;
                
                return View("Error");
            }
        }

        // VULNERABLE: XSS through URL parameters in JavaScript
        [HttpGet]
        public IActionResult Dashboard(string theme, string userId)
        {
            // VULNERABLE: User input passed to JavaScript without proper escaping
            ViewBag.JavaScriptCode = $@"
                <script>
                    var currentTheme = '{theme}';
                    var userId = '{userId}';
                    document.getElementById('theme-display').innerHTML = 'Current theme: ' + currentTheme;
                    document.getElementById('user-display').innerHTML = 'User ID: ' + userId;
                </script>";
            
            return View();
        }
    }

    // VULNERABLE: XSS in custom HTML helper
    public static class HtmlHelpers
    {
        public static string DisplayUserInput(string input)
        {
            // VULNERABLE: No HTML encoding applied
            return $"<span class='user-input'>{input}</span>";
        }

        public static string CreateAlert(string message, string type = "info")
        {
            // VULNERABLE: Direct HTML generation with user content
            return $"<div class='alert alert-{type}'>{message}</div>";
        }
    }

    // VULNERABLE: XSS in API Controller
    [ApiController]
    [Route("api/[controller]")]
    public class DataController : ControllerBase
    {
        [HttpGet("status")]
        public IActionResult GetStatus(string message)
        {
            // VULNERABLE: User input in HTML response from API
            var htmlContent = $@"
                <html>
                <body>
                    <h1>System Status</h1>
                    <p>Status message: {message}</p>
                    <p>Last updated: {DateTime.Now}</p>
                </body>
                </html>";

            return Content(htmlContent, "text/html");
        }

        [HttpPost("feedback")]
        public IActionResult SubmitFeedback([FromBody] FeedbackModel feedback)
        {
            // VULNERABLE: User input directly in response
            var responseHtml = $@"
                <div class='feedback-response'>
                    <h3>Thank you for your feedback!</h3>
                    <p>Name: {feedback.Name}</p>
                    <p>Email: {feedback.Email}</p>
                    <p>Message: {feedback.Message}</p>
                </div>";

            return Content(responseHtml, "text/html");
        }
    }

    public class FeedbackModel
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Message { get; set; }
    }
}
