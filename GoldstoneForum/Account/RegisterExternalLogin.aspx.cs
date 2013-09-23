using GoldstoneForum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Linq;
using Error_Handler_Control;

namespace GoldstoneForum.Account
{
    public partial class RegisterExternalLogin : System.Web.UI.Page
    {
        protected string ProviderName
        {
            get { return (string)ViewState["ProviderName"] ?? String.Empty; }
            private set { ViewState["ProviderName"] = value; }
        }

        protected string ProviderAccountKey
        {
            get { return (string)ViewState["ProviderAccountKey"] ?? String.Empty; }
            private set { ViewState["ProviderAccountKey"] = value; }
        }

        protected void Page_Load()
        {
            // Process the result from an auth provider in the request
            ProviderName = OpenAuthProviders.GetProviderNameFromRequest(Request);
            if (String.IsNullOrEmpty(ProviderName))
            {
                Response.Redirect("~/Account/Login");
            }
            if (!IsPostBack)
            {
                IAuthenticationManager manager = new AuthenticationIdentityManager(new IdentityStore()).Authentication;
                var auth = Context.GetOwinContext().Authentication;
                ClaimsIdentity id = manager.GetExternalIdentity(auth);
                var context = new ApplicationDbContext();
                var user = context.UserRoles.FirstOrDefault(u => u.User.UserName == id.Name);
                if (user != null)
                {
                    var userRole = user.Role.Name;
                    if (userRole == "Banned")
                    {
                        ErrorSuccessNotifier.AddErrorMessage("You are banned!");
                        ErrorSuccessNotifier.ShowAfterRedirect = true;
                        Response.Redirect("~/Account/Login");
                    }
                }
                IdentityResult result = manager.SignInExternalIdentity(auth, id);

                if (result.Success)
                {
                    OpenAuthProviders.RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
                }
                else if (User.Identity.IsAuthenticated)
                {
                    result = manager.LinkExternalIdentity(id, User.Identity.GetUserId());
                    if (result.Success)
                    {
                        OpenAuthProviders.RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
                    }
                    else
                    {
                        AddErrors(result);
                        return;
                    }
                }
                else
                {
                    userName.Text = id.Name;
                }
            }
        }

        protected void LogIn_Click(object sender, EventArgs e)
        {
            CreateAndLoginUser();
        }

        private void CreateAndLoginUser()
        {
            if (!IsValid)
            {
                return;
            }
            ApplicationUser user = new ApplicationUser();
            user.UserName = userName.Text;
            var filename = user.UserName + ".jpg";
            user.Avatar = filename;
            IAuthenticationManager manager = new AuthenticationIdentityManager(new IdentityStore(new ApplicationDbContext())).Authentication;
            IdentityResult result = manager.CreateAndSignInExternalUser(Context.GetOwinContext().Authentication, user);
            if (result.Success)
            {
                string urlToDownload = "http://graph.facebook.com/" + user.UserName + "/picture";
                string pathToSave = Server.MapPath("~/Avatar_Files/") + filename;
                WebClient client = new WebClient();
                client.DownloadFile(urlToDownload, pathToSave);
                OpenAuthProviders.RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
            }
            else
            {
                AddErrors(result);
                return;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }
    }
}