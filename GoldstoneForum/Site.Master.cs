using GoldstoneForum.Models;
using System;
using Error_Handler_Control;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Linq;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GoldstoneForum
{
    public partial class SiteMaster : MasterPage
    {
        private const string AntiXsrfTokenKey = "__AntiXsrfToken";
        private const string AntiXsrfUserNameKey = "__AntiXsrfUserName";
        private string _antiXsrfTokenValue;

        protected void Page_Init(object sender, EventArgs e)
        {
            if (Context.User.Identity.IsAuthenticated)
            {
                var context = new ApplicationDbContext();
                var username = Context.User.Identity.Name;
                var user = context.Users.FirstOrDefault(u => u.UserName == username);
                if (user == null)
                {
                    Context.GetOwinContext().Authentication.SignOut();
                    return;
                }
            }

            // The code below helps to protect against XSRF attacks
            var requestCookie = Request.Cookies[AntiXsrfTokenKey];
            Guid requestCookieGuidValue;
            if (requestCookie != null && Guid.TryParse(requestCookie.Value, out requestCookieGuidValue))
            {
                // Use the Anti-XSRF token from the cookie
                _antiXsrfTokenValue = requestCookie.Value;
                Page.ViewStateUserKey = _antiXsrfTokenValue;
            }
            else
            {
                // Generate a new Anti-XSRF token and save to the cookie
                _antiXsrfTokenValue = Guid.NewGuid().ToString("N");
                Page.ViewStateUserKey = _antiXsrfTokenValue;

                var responseCookie = new HttpCookie(AntiXsrfTokenKey)
                {
                    HttpOnly = true,
                    Value = _antiXsrfTokenValue
                };
                if (FormsAuthentication.RequireSSL && Request.IsSecureConnection)
                {
                    responseCookie.Secure = true;
                }
                Response.Cookies.Set(responseCookie);
            }

            Page.PreLoad += master_Page_PreLoad;
        }

        protected void master_Page_PreLoad(object sender, EventArgs e)
        {
            if (!IsPostBack)
            {
                // Set Anti-XSRF token
                ViewState[AntiXsrfTokenKey] = Page.ViewStateUserKey;
                ViewState[AntiXsrfUserNameKey] = Context.User.Identity.Name ?? String.Empty;
            }
            else
            {
                // Validate the Anti-XSRF token
                if ((string)ViewState[AntiXsrfTokenKey] != _antiXsrfTokenValue
                    || (string)ViewState[AntiXsrfUserNameKey] != (Context.User.Identity.Name ?? String.Empty))
                {
                    throw new InvalidOperationException("Validation of Anti-XSRF token failed.");
                }
            }
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            var userName = Context.User.Identity.Name;
            var context = new ApplicationDbContext();
            if (userName.Length > 0)
            {
                var user = context.Users.FirstOrDefault(u => u.UserName == userName);
                var avatarUrl = user.Avatar;
                var avatar = LoginView.FindControl("ImageAvatar") as Image;
                avatar.ImageUrl = "Avatar_Files/" + avatarUrl;
                avatar.Width = 30;
                avatar.Height = 30;
            }

            var categories = context.Categories.ToList();
            this.RepeaterSidebar.DataSource = categories;
            this.RepeaterSidebar.DataBind();
        }

        protected void Unnamed_LoggingOut(object sender, LoginCancelEventArgs e)
        {
            Context.GetOwinContext().Authentication.SignOut();
        }

        protected bool IsMenuItemVIsible(string url)
        {
            if (url == "/AskQuestion" && !this.Context.User.Identity.IsAuthenticated)
            {
                return false;
            }

            if (url == "/Admin/Users" && !this.Context.User.IsInRole("Admin"))
            {
                return false;
            }

            return true;
        }

        protected void ButtonSearch_Click(object sender, EventArgs e)
        {
            var searchQuery = this.TextBoxSearch.Text;
            if (searchQuery.Length > 200)
            {
                ErrorSuccessNotifier.AddErrorMessage("Search content must be less than 200 chars.");
            }
            else
            {
                var encode = Server.UrlEncode(searchQuery);
                Response.Redirect("SearchResults.aspx?q=" + encode);
            }
        }
    }
}