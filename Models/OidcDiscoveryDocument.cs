namespace Autherization_test.Models;

public class OidcDiscoveryDocument
{
    public string jwks_uri { init; get; }
    public string userinfo_endpoint { init; get; }
    public string authorization_endpoint { init; get; }
    public string token_endpoint { init; get; }
}