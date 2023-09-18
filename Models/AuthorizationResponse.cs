namespace Autherization_test.Models;

public class AuthorizationResponse
{
    
    public string code { init; get; }
    
    public string state { init; get; }
    
    public string? session_state { init; get; }
}