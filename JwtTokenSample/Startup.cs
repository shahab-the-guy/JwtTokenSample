using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JwtTokenSample.Configurations;
using MediatR;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtTokenSample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        private IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddOpenApiDocument(a => a.Title = "Generate Json Web Tokens");

            services.AddMediatR(typeof(Startup).Assembly);

            var jwtConfiguration = Configuration.GetSection("Jwt").Get<JwtConfiguration>();
            services.Configure<JwtConfiguration>(instance => Configuration.Bind("Jwt" , instance));
            services.AddScoped(provider => provider.GetRequiredService<IOptionsSnapshot<JwtConfiguration>>().Value);

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidIssuer = jwtConfiguration.Issuer,
                        ValidAudience = jwtConfiguration.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.Password))
                    };

                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = ValidateToken,
                    };
                });
        }
        
        public static string GetTokenFromHeader(IHeaderDictionary requestHeaders)
        {
            if (!requestHeaders.TryGetValue("Authorization", out var authorizationHeader))
                throw new InvalidOperationException("Authorization token does not exists");

            var authorization = authorizationHeader.FirstOrDefault()!.Split(" ");

            var type = authorization[0];

            if (type != "Bearer") throw new InvalidOperationException("You should provide a Bearer token");

            var value = authorization[1] ?? throw new InvalidOperationException("Authorization token does not exists");
            return value;
        }

        public static Task ValidateToken(MessageReceivedContext context)
        {
            try
            {
                context.Token = GetTokenFromHeader(context.Request.Headers);

                var tokenHandler = new JwtSecurityTokenHandler();
                tokenHandler.ValidateToken(context.Token, context.Options.TokenValidationParameters, out var validatedToken);

                var jwtSecurityToken = validatedToken as JwtSecurityToken;

                context.Principal = new ClaimsPrincipal();

                Debug.Assert(jwtSecurityToken != null, nameof(jwtSecurityToken) + " != null");

                var claimsIdentity = new ClaimsIdentity(jwtSecurityToken.Claims.ToList(), "JwtBearerToken",
                    ClaimTypes.NameIdentifier, ClaimTypes.Role);
                
                context.Principal.AddIdentity(claimsIdentity);

                context.Success();

                return Task.CompletedTask;
            }
            catch (Exception e)
            {
                context.Fail(e);
            }

            return Task.CompletedTask;
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseOpenApi();
            app.UseSwaggerUi3();

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}
