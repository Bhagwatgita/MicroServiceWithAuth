using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Ocelot.Middleware;
using Ocelot.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Gateway
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args)
        {
            return WebHost.CreateDefaultBuilder(args)
                          .UseStartup<Startup>()
                          .ConfigureAppConfiguration((hostingContext, config) =>
                          {
                              config.AddJsonFile("configuration.json")
                              .AddEnvironmentVariables();
                          })
                          .ConfigureServices(s =>
                          {
                              s.AddAuthentication(x =>
                              {
                                  x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                                  x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                              })
                            .AddJwtBearer(x =>
                            {
                                x.RequireHttpsMetadata = false;
                                x.SaveToken = true;
                                x.TokenValidationParameters = new TokenValidationParameters
                                {
                                    ValidateIssuerSigningKey = true,
                                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("3ce1637ed40041cd94d4853d3e766c4d")),
                                    ValidateIssuer = false,
                                    ValidateAudience = false
                                };
                            });
                              s.AddOcelot();
                          })
                          .Configure(app =>
                          {
                              app.UseAuthentication();
                              app.UseOcelot().Wait();
                          })
                          .ConfigureLogging((hostingContext, logging) =>
                          {
                              //add your logging
                          })
                          .UseIISIntegration()
                          .Build();
        }
    }
}
