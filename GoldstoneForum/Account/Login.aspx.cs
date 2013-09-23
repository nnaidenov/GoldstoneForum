using Error_Handler_Control;
using GoldstoneForum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Linq;
using System.Web;
using System.Web.UI;

namespace GoldstoneForum.Account
{
    public partial class Login : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            RegisterHyperLink.NavigateUrl = "Register";
            OpenAuthLogin.ReturnUrl = Request.QueryString["ReturnUrl"];
            var returnUrl = HttpUtility.UrlEncode(Request.QueryString["ReturnUrl"]);
            if (!String.IsNullOrEmpty(returnUrl))
            {
                RegisterHyperLink.NavigateUrl += "?ReturnUrl=" + returnUrl;
            }
        }

        protected void LogIn(object sender, EventArgs e)
        {
          
            if (IsValid)
            {
                // Validate the user password
                IAuthenticationManager manager = new AuthenticationIdentityManager(new IdentityStore(new ApplicationDbContext())).Authentication;
                IdentityResult result = manager.CheckPasswordAndSignIn(Context.GetOwinContext().Authentication, UserName.Text, Password.Text, RememberMe.Checked);
                if (result.Success)
                {
                    var context = new ApplicationDbContext();
                    var curUserName = UserName.Text;
                    var userId = context.Users.FirstOrDefault(u => u.UserName == curUserName).Id;
                    var userRole = context.UserRoles.FirstOrDefault(u => u.UserId == userId).Role.Name;
                    if (userRole == "Banned")
                    {
                        ErrorSuccessNotifier.AddErrorMessage("You are banned!");
                        return;
                    }
                    OpenAuthProviders.RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
                }
                else
                {
                    ErrorSuccessNotifier.AddErrorMessage(result.Errors.FirstOrDefault());
                }
            }
        }
    }
}