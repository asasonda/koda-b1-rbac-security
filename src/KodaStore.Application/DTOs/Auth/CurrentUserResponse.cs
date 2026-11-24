namespace KodaStore.Application.DTOs.Auth;

public sealed class CurrentUserResponse(
    Guid Id, 
    string Email,
    IReadOnlyList<string> Roles
);