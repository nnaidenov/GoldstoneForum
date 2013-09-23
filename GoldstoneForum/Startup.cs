using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(GoldstoneForum.Startup))]
namespace GoldstoneForum
{
    public partial class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureAuth(app);
        }
    }
}
