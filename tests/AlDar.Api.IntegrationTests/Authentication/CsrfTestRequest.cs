using System.Net.Http.Json;
using System.Text.Json;

namespace AlDar.Api.IntegrationTests.Authentication;

internal static class CsrfTestRequest
{
    public static async Task<HttpResponseMessage> PostAsync(
        HttpClient client,
        string path,
        object? body = null,
        string? refreshToken = null)
    {
        // Fetch the matching request token and cookie.
        using var csrfResponse = await client.GetAsync("/api/auth/csrf");
        csrfResponse.EnsureSuccessStatusCode();

        var csrfJson = await csrfResponse.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(csrfJson);
        var requestToken = document.RootElement
            .GetProperty("token")
            .GetString();

        if (string.IsNullOrWhiteSpace(requestToken))
            throw new InvalidOperationException(
                "The API returned an empty antiforgery request token.");

        var csrfCookie = csrfResponse.Headers
            .GetValues("Set-Cookie")
            .Single(value => value.StartsWith(
                "aldar.csrf=", StringComparison.OrdinalIgnoreCase))
            .Split(';', 2)[0];

        using var request = new HttpRequestMessage(HttpMethod.Post, path);

        request.Headers.TryAddWithoutValidation(
            "X-CSRF-TOKEN", requestToken);

        var cookies = csrfCookie;
        if (!string.IsNullOrWhiteSpace(refreshToken))
            cookies += $"; aldar.refresh={refreshToken}";

        request.Headers.TryAddWithoutValidation("Cookie", cookies);

        if (body is not null)
            request.Content = JsonContent.Create(body);

        return await client.SendAsync(request);
    }
}
