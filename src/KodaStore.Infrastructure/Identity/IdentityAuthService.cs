using KodaStore.Application.DTOs.Auth;
using KodaStore.Application.Security;
using KodaStore.Application.Services;
using KodaStore.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

namespace KodaStore.Infrastructure.Identity;

public sealed class IdentityAuthService(UserManager<AppUser> user, AppDbContext db) : IAuthService
{
    private readonly UserManager<AppUser> _user = user;
    private readonly AppDbContext _db = db;

    public async Task<LoginResult> LogisAsync(LoginRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var email = request.Email.Trim();
        var user = await _user.FindByEmailAsync(email);

        if (user is null)
        {
            return new LoginResult(false, null);
        }

        var passwordValid = await _user.CheckPasswordAsync(user, request.Password);

        if (!passwordValid)
        {
            return new LoginResult(false, null);
        }

        var roles = await _user.GetRolesAsync(user);
        var response = new AuthUserResponse(
            user.Id, user.Email!, user.DisplayName, roles.ToArray()
        );
        return new LoginResult(true, response);
    }

    public async Task<RegisterResult> RegisterAsync(RegisterRequest request, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        var email = request.Email.Trim();
        var existingUser = await _user.FindByEmailAsync(email);

        if(existingUser is not null)
        {
            return new RegisterResult(RegisterStatus.DuplicateEmail, null, ["Email sudah terdaftar"]);
        }

        var user = new AppUser{
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            DisplayName = request.DisplayName.Trim(),
            CreatedAtUtc = DateTimeOffset.UtcNow 
        };

        await using var transaction = await _db.Database.BeginTransactionAsync(ct);
        try
        {
            var createResult = await _user.CreateAsync(user,request.Password);
            if (!createResult.Succeeded)
            {
                await transaction.RollbackAsync(ct);
                var error = createResult.Errors.ToArray();
                var duplicate = error.Any(error => error.Code is "DuplicateEmail" or "DuplicateUserName");

                if (duplicate)
                {
                    return new RegisterResult(RegisterStatus.DuplicateEmail, null, ["Email sudah terdaftar"]);
                }

                return new RegisterResult(RegisterStatus.ValidationError, null, error.Select(error => error.Description).ToArray());
            }

            var roleResult = await _user.AddToRoleAsync(user, AppRole.Customer);
            if (!roleResult.Succeeded)
            {
                var errors = string.Join("; ", roleResult.Errors.Select(error => error.Description));
                throw new InvalidOperationException($"Gagal memberikan role CUSTOMER: {errors}");
            }

            await transaction.CommitAsync(ct);
        }
        catch (DbUpdateException e) when (e.InnerException is SqlException sqlError && sqlError.Number is 2601 or 2627)
        {
            return new RegisterResult(RegisterStatus.DuplicateEmail, null, ["Email sudah terdaftar"]);
        }

        var roles = await _user.GetRolesAsync(user);
        var response = new AuthUserResponse(
            user.Id,
            user.Email,
            user.DisplayName,
            roles.ToArray()
        );

        return new RegisterResult(RegisterStatus.Created, response, []);
    }
}