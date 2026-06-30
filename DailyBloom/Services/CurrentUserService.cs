using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;

namespace DailyBloom.Services;

/// <summary>
/// Keeps track of who is logged in for the current browser tab.
/// We use ProtectedSessionStorage (encrypted browser sessionStorage) instead of
/// classic cookie auth, because in interactive Blazor Server, headers can't be
/// changed once the page has started rendering. This keeps things simple and
/// still keeps the session private to the user's browser tab.
/// </summary>
public class CurrentUserService : AuthenticationStateProvider
{
    private readonly ProtectedSessionStorage _sessionStorage;
    private ClaimsPrincipal _anonymous = new(new ClaimsIdentity());
    public int? CurrentUserId { get; private set; }
    public string? CurrentUserName { get; private set; }

    public CurrentUserService(ProtectedSessionStorage sessionStorage)
    {
        _sessionStorage = sessionStorage;
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        try
        {
            var result = await _sessionStorage.GetAsync<int>("userId");
            var nameResult = await _sessionStorage.GetAsync<string>("userName");
            if (result.Success && result.Value != 0)
            {
                CurrentUserId = result.Value;
                CurrentUserName = nameResult.Value;
                var identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, result.Value.ToString()),
                    new Claim(ClaimTypes.Name, nameResult.Value ?? "")
                }, "DailyBloom");
                return new AuthenticationState(new ClaimsPrincipal(identity));
            }
        }
        catch
        {
            // storage not yet available during prerender; treat as anonymous
        }
        return new AuthenticationState(_anonymous);
    }

    public async Task SignInAsync(int userId, string name)
    {
        CurrentUserId = userId;
        CurrentUserName = name;
        await _sessionStorage.SetAsync("userId", userId);
        await _sessionStorage.SetAsync("userName", name);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task SignOutAsync()
    {
        CurrentUserId = null;
        CurrentUserName = null;
        await _sessionStorage.DeleteAsync("userId");
        await _sessionStorage.DeleteAsync("userName");
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(_anonymous)));
    }
}
