using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Autherization_test.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

namespace Autherization_test;

public class OidcHelper
{
    private readonly OidcDiscoveryDocument _config;
    private readonly OidcOptions _options;

    public OidcHelper(OidcOptions options, OidcDiscoveryDocument config)
    {
        _options = options;
        _config = config;
    }

    public static async Task<OidcHelper> Create(OidcOptions options)
    {
        return new OidcHelper(options, await FetchDiscoveryDocument(options.Provider));
    }

    public static async Task<OidcDiscoveryDocument> FetchDiscoveryDocument(string providerUri)
    {
        var response = await new HttpClient().GetAsync($"{providerUri}/.well-known/openid-configuration");
        var content = await response.Content.ReadFromJsonAsync<OidcDiscoveryDocument>();
        return content!;
    }

    public string AuthorizationUri(string state, string codeVerifier)
    {
        var parameters = new Dictionary<string, string?>
        {
            { "client_id", _options.ClientId},
            { "scope", "openid email phone address profile" },
            { "response_type", "code" },
            { "redirect_uri", _options.RedirectUri },
            { "prompt", "login" },
            { "state", state },
            { "code_challenge_method", "S256" },
            { "code_challenge", S256(codeVerifier) }
        };
        var authorizationUri = QueryHelpers.AddQueryString(_config.authorization_endpoint, parameters);
        return authorizationUri;
    }

    public string S256(string input)
    {
        byte[] hash;
        using (var hasher = SHA256.Create())
        {
            hash = hasher.ComputeHash(Encoding.UTF8.GetBytes(input));
        }

        return Base64UrlTextEncoder.Encode(hash);
    }

    public async Task<TokenResponse> ExchangeAuthorizationCode(string code, string codeVerifier)
    {
        var parameters = new Dictionary<string, string?>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", _options.RedirectUri },
            { "code_verifier", codeVerifier },
            { "client_id", _options.ClientId },
            { "client_secret", _options.ClientSecret }
        };
        var tokenResponse =
            await new HttpClient().PostAsync(_config.token_endpoint, new FormUrlEncodedContent(parameters));
        var tokenBody = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
        return tokenBody!;
    }

    public async Task<Tuple<TokenValidationResult, JwtSecurityToken>> ReadAndValidateToken(string jwt)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.ReadJwtToken(jwt);
        var validation = await tokenHandler.ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            IssuerSigningKeys = await FetchValidationKeys(),
            ValidAudiences = new[] { _options.ClientId },
            ValidIssuer = _options.Provider,
            ValidateLifetime = true,
            ValidateAudience = true,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            ValidateTokenReplay = true
        });
        return new Tuple<TokenValidationResult, JwtSecurityToken>(validation, token);
    }

    public async Task<IList<JsonWebKey>> FetchValidationKeys()
    {
        var response = await new HttpClient().GetAsync(_config.jwks_uri);
        var keys = await response.Content.ReadAsStringAsync();
        var jwks = JsonWebKeySet.Create(keys);
        jwks.SkipUnresolvedJsonWebKeys = false;
        return jwks.Keys;
    }

    public async Task<object> FetchUserInfo(string accessToken)
    {
        var http = new HttpClient
        {
            DefaultRequestHeaders =
            {
                { "Authorization", "Bearer " + accessToken }
            }
        };
        var response = await http.GetAsync(_config.userinfo_endpoint);
        var content = await response.Content.ReadFromJsonAsync<object?>();
        return content!;
    }
}