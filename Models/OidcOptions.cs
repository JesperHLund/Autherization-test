namespace Autherization_test.Models;

public class OidcOptions
{
    public string Provider { init; get; }
    public string RedirectUri { init; get; }

    public string ClientId { init; get; }

    public string ClientSecret { init; get; }
}