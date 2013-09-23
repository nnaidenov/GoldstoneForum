using Error_Handler_Control;
using GoldstoneForum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.UI;

namespace GoldstoneForum.Account
{
    public partial class Register : Page
    {
        protected void CreateUser_Click(object sender, EventArgs e)
        {
            string userName = UserName.Text;
            string email = Email.Text;
            string filename = "default.png";
            if (UploadAvatar.HasFile)
            {
                if (UploadAvatar.PostedFile.ContentType == "image/jpeg" ||
                    UploadAvatar.PostedFile.ContentType == "image/gif" ||
                    UploadAvatar.PostedFile.ContentType == "image/png")
                {
                    if (UploadAvatar.PostedFile.ContentLength < 102400)
                    {
                        filename = userName + Path.GetExtension(UploadAvatar.FileName);
                        UploadAvatar.SaveAs(Server.MapPath("~/Avatar_Files/") + filename);
                    }
                    else
                    {
                        ErrorSuccessNotifier.AddErrorMessage("Upload status: The file has to be less than 100 kb!");
                        return;
                    }
                }
                else
                {
                    ErrorSuccessNotifier.AddErrorMessage("Upload status: Only JPEG files are accepted!");
                    return;
                }
            }

            var manager = new AuthenticationIdentityManager(new IdentityStore(new ApplicationDbContext()));
            ApplicationUser u = new ApplicationUser()
            {
                UserName = userName,
                Email = email,
                Avatar = filename

            };
            IdentityResult result = manager.Users.CreateLocalUser(u, Password.Text);
            if (result.Success)
            {
                manager.Authentication.SignIn(Context.GetOwinContext().Authentication, u.Id, isPersistent: false);
                OpenAuthProviders.RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
            }
            else
            {
                ErrorSuccessNotifier.AddErrorMessage(result.Errors.FirstOrDefault());
            }
        }
    }
}