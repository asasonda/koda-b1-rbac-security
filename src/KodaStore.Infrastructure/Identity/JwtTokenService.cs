using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using KodaStore.Application.DTOs;
using KodaStore.Application.DTOs.Auth;
using KodaStore.Application.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace KodaStore.Infrastructure.Identity;

public sealed class JwtTokenService(IOptions<JwtOptions> option) : IJwtTokenService
{
    private readonly JwtOptions _option = option.Value;
    public IssuedAccessToken IssuedAccessToken(AuthUserResponse user)
    {
        var now = DateTimeOffset.UtcNow;

        var expiredAtUtc = now.AddMinutes(_option.AccessTokenMinutes);
        var keyBytes = Convert.FromBase64String(_option.SigninKeyBase64);
        var securityKey = new SymmetricSecurityKey(keyBytes);
        var signinCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString("D")),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)
        };

        foreach(var role in user.Roles.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            claims.Add(new Claim("role", role));
        }

        var jwt = new JwtSecurityToken(
            issuer: _option.Issuer,
            audience: _option.Audience,
            claims: claims,
            notBefore: now.UtcDateTime,
            expires: expiredAtUtc.UtcDateTime,
            signingCredentials: signinCredentials
        );

        var accessToken = new JwtSecurityTokenHandler().WriteToken(jwt);
        return new IssuedAccessToken(accessToken, expiredAtUtc);
    }
}