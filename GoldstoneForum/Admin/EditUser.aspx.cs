using Error_Handler_Control;
using GoldstoneForum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GoldstoneForum.Admin
{
    public partial class EditUser : System.Web.UI.Page
    {
        private string userId;

        protected void Page_Load(object sender, EventArgs e)
        {
            userId = this.Request.QueryString["userId"];

            var context = new ApplicationDbContext();
            var user = context.Users.Find(userId);
            if (user.Roles.Count > 0)
            {
                if (user.Roles.First().Role.Name == "Banned")
                {
                    this.ButtonBAN.Text = "Unban User";
                    this.ButtonBAN.OnClientClick = "return confirm('Do you want to Unban user ?');";
                }
                else if (user.Roles.First().Role.Name == "Admin")
                {
                    this.ButtonAdmin.Text = "Remove Admin";
                    this.ButtonAdmin.OnClientClick = "return confirm('Do you want to remove admin?');";
                }
            }
        }

        protected void Page_PreRender(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var user = context.Users.Find(userId);
            this.TextBoxUserName.Text = user.UserName;
            this.TextBoxEmail.Text = user.Email;            
        }

        protected void LinkButtonReturn_Click(object sender, EventArgs e)
        {
            Response.Redirect("~/Admin/Users");
        }
        protected void LinkButtonSaveUser_Click(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var user = context.Users.Find(userId);
            user.UserName = this.TextBoxUserName.Text;
            user.Email = this.TextBoxEmail.Text;
            if (UploadAvatar.HasFile)
            {
                if (UploadAvatar.PostedFile.ContentType == "image/jpeg" ||
                    UploadAvatar.PostedFile.ContentType == "image/gif" ||
                    UploadAvatar.PostedFile.ContentType == "image/png")
                {
                    if (UploadAvatar.PostedFile.ContentLength < 102400)
                    {

                        var filename = user.UserName + Path.GetExtension(UploadAvatar.FileName);
                        UploadAvatar.SaveAs(Server.MapPath("~/Avatar_Files/") + filename);
                        user.Avatar = filename;
                    }
                    else
                    {
                        ErrorSuccessNotifier.AddErrorMessage("Upload status: The file has to be less than 100 kb!");
                        return;
                    }
                }
                else
                {
                    ErrorSuccessNotifier.AddErrorMessage("Upload status: Only JPEG, Gif and PNG files are accepted!");
                    return;
                }
            }
            try
            {
                context.SaveChanges();
                ErrorSuccessNotifier.AddSuccessMessage("User's data is updated!");
                ErrorSuccessNotifier.ShowAfterRedirect = true;
                Response.Redirect("~/Admin/Users", false);
            }
            catch (Exception ex)
            {
                ErrorSuccessNotifier.AddErrorMessage(ex);
            }            
        }

        protected void ButtonBAN_Click(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var user = context.Users.Find(userId);
            var manager = new AuthenticationIdentityManager(new IdentityStore(new ApplicationDbContext()));

            if (user.Roles.Count == 0 || user.Roles.First().Role.Name == "Admin")
            {
                var roleId = "2";
                manager.Roles.AddUserToRoleAsync(userId, roleId);
                ErrorSuccessNotifier.AddInfoMessage("The User has been banned!");
                this.ButtonBAN.Text = "Unban User";
                this.ButtonBAN.OnClientClick = "return confirm('Do you want to Unban user ?');";
            }
            else
            {
                var roleId = user.Roles.First().RoleId;
                manager.Roles.RemoveUserFromRoleAsync(userId, roleId);
                ErrorSuccessNotifier.AddInfoMessage("The User has been unbanned!");
                this.ButtonBAN.Text = "BAN User";
                this.ButtonBAN.OnClientClick = "return confirm('Do you want to Ban user ?');";
            }

        }

        protected void ButtonAdmin_Click(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var user = context.Users.Find(userId);

            var manager = new AuthenticationIdentityManager(new IdentityStore(new ApplicationDbContext()));

            if (user.Roles.Count == 0 || user.Roles.First().Role.Name == "Banned")
            {
                var roleId = "1";
                manager.Roles.AddUserToRoleAsync(userId, roleId);
                ErrorSuccessNotifier.AddInfoMessage("The User is an administrator!");
                this.ButtonAdmin.Text = "Remove Admin";
                this.ButtonAdmin.OnClientClick = "return confirm('Do you want to remove admin?');";
            }
            else
            {
                var roleId = user.Roles.First().RoleId;
                manager.Roles.RemoveUserFromRoleAsync(userId, roleId);
                ErrorSuccessNotifier.AddInfoMessage("The User is not an administrator!");
                this.ButtonAdmin.Text = "Add Admin";
                this.ButtonAdmin.OnClientClick = "return confirm('Do you want to create admin?');";
            }
        }
    }
}