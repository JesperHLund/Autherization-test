using System.Diagnostics;
using System.Security.Cryptography;
using Autherization_test.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Autherization_test.Controllers;

public class HomeController : Controller
{
    private readonly IConfiguration _config;
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }

    private async Task<OidcHelper> CreateOidcHelper()
    {
        var options = _config.GetRequiredSection("OpenIDConnect").Get<OidcOptions>();
        return await OidcHelper.Create(options!);
    }

    public IActionResult Index()
    {
        return View();
    }

    public async Task<IActionResult> Login()
    {
        var state = Base64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var codeVerifier = Base64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        HttpContext.Session.SetString("state", state);
        HttpContext.Session.SetString("code_verifier", codeVerifier);
        await HttpContext.Session.CommitAsync();
        var helper = await CreateOidcHelper();
        return Redirect(helper.AuthorizationUri(state, codeVerifier));
    }

    public async Task<IActionResult> Callback(AuthorizationResponse authResponse)
    {
        if (authResponse.state != HttpContext.Session.GetString("state")) return Unauthorized();

        var codeVerifier = HttpContext.Session.GetString("code_verifier");
        var helper = await CreateOidcHelper();
        var tokenBody = await helper.ExchangeAuthorizationCode(authResponse.code, codeVerifier!);
        var (validation, idToken) = await helper.ReadAndValidateToken(tokenBody.id_token);
        if (!validation.IsValid) return Unauthorized("ID token validation failed");
        var userInfo = await helper.FetchUserInfo(tokenBody.access_token);
        ViewData["id_token"] = idToken;
        ViewData["userinfo"] = userInfo;
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}