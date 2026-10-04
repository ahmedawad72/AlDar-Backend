

using AlDar.Application.Authentication;

namespace AlDar.Application.Abstractions
{
    public interface IEmailService
    {
        Task SendAsync(
            string to,
            string subject,
            string htmlBody,
            CancellationToken cancellationToken = default);
    }
}
