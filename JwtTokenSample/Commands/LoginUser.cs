using MediatR;

namespace JwtTokenSample.Commands
{
    public class LoginUser : IRequest<string>
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
