using AlDar.Application.Abstractions;

namespace AlDar.Api.IntegrationTests.Fakes;

public sealed class TestEmailService : IEmailService
{
    public List<TestEmailMessage> SentEmails { get; } = [];

    public Task SendAsync( string to, string subject, string htmlBody,CancellationToken cancellationToken = default)
    {
        SentEmails.Add( new TestEmailMessage( to,subject, htmlBody));

        return Task.CompletedTask;
    }

    public void Clear()
    {
        SentEmails.Clear();
    }
}

public sealed record TestEmailMessage( string To, string Subject, string HtmlBody);