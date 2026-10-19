namespace AlDar.Application.Exceptions;

public sealed class EmailNotConfirmedException : Exception
{
    public const string ErrorCode = "EmailNotConfirmed";

    public EmailNotConfirmedException()
        : base("Email confirmation is required before login.")
    {
    }
}