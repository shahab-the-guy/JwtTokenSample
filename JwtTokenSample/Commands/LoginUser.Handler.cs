using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JwtTokenSample.Configurations;
using MediatR;
using Microsoft.IdentityModel.Tokens;

namespace JwtTokenSample.Commands
{
    public sealed class LoginUserHandler : IRequestHandler<LoginUser, string>
    {
        private readonly JwtConfiguration _jwt;

        public LoginUserHandler(JwtConfiguration jwt)
        {
            _jwt = jwt;
        }
        
        public Task<string> Handle(LoginUser request, CancellationToken cancellationToken)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Password));
            var header = new JwtHeader(new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature));

            // this should be read from a storage, e.g. SQL Server, MongoDB
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,request.Username),
                // new Claim(JwtRegisteredClaimNames.Email,user.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, request.Username),
                new Claim(ClaimTypes.Role, "admin"),
            };
            // **************************************************************
            
            var payload = new JwtPayload(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims, null,
                expires: DateTime.UtcNow.AddDays(_jwt.ExpiryDays)
                ,null);

            var token = new JwtSecurityToken(header, payload);

            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenString = tokenHandler.WriteToken(token);

            return Task.FromResult(tokenString);
        }
    }
}
