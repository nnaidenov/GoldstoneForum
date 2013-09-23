using Error_Handler_Control;
using GoldstoneForum.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GoldstoneForum
{
    public partial class AskQuestion : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!User.Identity.IsAuthenticated)
            {
                Response.Redirect("~/Default.aspx");
            }
        }

        protected void Page_PreRender(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var categories = context.Categories.ToList();
            this.DropDownListCategories.DataSource = categories;
            this.DataBind();
        }

        protected void AskQUestion_Click(object sender, EventArgs e)
        {
            var user = this.User.Identity.Name;
            var context = new ApplicationDbContext();
            var dbUser = context.Users.FirstOrDefault(u => u.UserName == user);
            var title = this.TextBoxTitle.Text;
            var questText = this.QuestionText.Text;
            int categoryId = Convert.ToInt32(this.DropDownListCategories.SelectedItem.Value);
            var category = context.Categories.Find(categoryId);

            var newQ = new Models.Question
            {
                Title = title,
                Text = questText,
                User = dbUser,
                Category = category,
                DatePosted = DateTime.Now
            };

            context.Questions.Add(newQ);

            context.SaveChanges();

            ErrorSuccessNotifier.ShowAfterRedirect = true;
            ErrorSuccessNotifier.AddSuccessMessage("Question created");

            Response.Redirect("~/QuestionForm.aspx?id=" + newQ.Id);
        }
    }
}