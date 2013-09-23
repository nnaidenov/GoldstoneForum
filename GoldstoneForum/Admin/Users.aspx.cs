using GoldstoneForum.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GoldstoneForum
{
    public partial class Users : System.Web.UI.Page
    {
        protected void Page_PreRender(object sender, EventArgs e)
        {
            this.GridViewUsers.DataBind();
            
        }

        public IQueryable<ApplicationUser> GridViewUsers_GetData()
        {
            ApplicationDbContext context = new ApplicationDbContext();
            var user = context.Users.Where(u => u.UserName != this.User.Identity.Name).OrderBy(q => q.Id);
            return user;
        }


        protected void LinkButtonBanUser_Command(object sender, CommandEventArgs e)
        {
            var manager = new AuthenticationIdentityManager(new IdentityStore(new ApplicationDbContext()));

            string roleBanId = "2";
            manager.Roles.AddUserToRoleAsync(e.CommandArgument.ToString(), roleBanId);
            
        }
    }
}