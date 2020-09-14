using System.Threading.Tasks;
using JwtTokenSample.Commands;
using MediatR;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtTokenSample.Controllers
{
    public sealed class AccountController : BaseController
    {
        private readonly IMediator _mediator;

        public AccountController(IMediator mediator)
        {
            _mediator = mediator;
        }
        
        [HttpPost("login")]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
        public async Task<IActionResult> Login([FromBody]LoginUser loginCommand)
        {
            var jwt = await _mediator.Send(loginCommand);
            
            return Ok(jwt);
        }
    }
}
