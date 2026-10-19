namespace AlDar.Application.Exceptions;

public sealed class AccountLockedException : Exception
{
    public const string ErrorCode = "AccountLocked";

    public DateTimeOffset? LockedUntilUtc { get; }

    public AccountLockedException(DateTimeOffset? lockedUntilUtc)
        : base( "Your account is temporarily locked due to multiple failed login attempts.")
    {
        LockedUntilUtc = lockedUntilUtc;
    }
}