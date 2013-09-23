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
    public partial class Category : System.Web.UI.Page
    {
        protected void Page_PreRender(object sender, EventArgs e)
        {
            int id = 0;// = Convert.ToInt32(Request.QueryString["Id"]);

            if (!int.TryParse(Request.QueryString["Id"], out id))
            {
                this.Response.Redirect("~/Default.aspx");
            }

            var context = new ApplicationDbContext();
            var category = context.Categories.Find(id);
            this.CategoryTitle.Text = category.Name;
            this.CategoryTitle.DataBind();

            if (User.Identity.IsAuthenticated && User.IsInRole("Admin"))
            {
                this.ButtonEditCategory.Visible = true;
                this.ButtonDeleteCategory.Visible = true;
                this.CategoryTitle.Visible = false;
                this.TextBoxCategoryTitle.Visible = true;
                this.TextBoxCategoryTitle.Text = category.Name;
            }
        }

        public IQueryable<GoldstoneForum.Models.Question> ListViewCategories_GetData()
        {
            int id = Convert.ToInt32(Request.QueryString["Id"]);
            var context = new ApplicationDbContext();
            var questions = context.Questions.Where(quest => quest.Category.Id == id);
            return questions;
        }

        protected void Vote_Command(object sender, CommandEventArgs e)
        {
            int id = Convert.ToInt32(e.CommandArgument);
            var context = new ApplicationDbContext();
            var question = context.Questions.Find(id);
            var username = this.User.Identity.Name;
            var user = context.Users.FirstOrDefault(u => u.UserName == username);

            if (e.CommandName == "Vote")
            {
                question.Votes.Add(new QuestionVotes() { User = user });
            }

            if (e.CommandName == "Unvote")
            {
                var vote = question.Votes.FirstOrDefault(v => v.User == user);
                question.Votes.Remove(vote);
            }

            context.SaveChanges();
            this.Page.DataBind();
        }


        protected bool CanUserVoteOnAnswer(int id)
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }

            var context = new ApplicationDbContext();

            var question = context.Questions.Find(id);
            var username = this.User.Identity.Name;
            var user = context.Users.FirstOrDefault(u => u.UserName == username);

            if (question.Votes.Any(v => v.User == user))
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        protected bool CanUserUnVoteOnAnswer(int id)
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }
            else
            {
                return !CanUserVoteOnAnswer(id);
            }
        }

        protected void ButtonEditCategory_Click(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();

            int id = Convert.ToInt32(Request.QueryString["Id"]);
            Models.Category cat = context.Categories.Find(id);

            string oldCatName = cat.Name;
            string newCatName = this.TextBoxCategoryTitle.Text;

            if (string.IsNullOrWhiteSpace(newCatName))
            {
                ErrorSuccessNotifier.AddErrorMessage("Please enter category non empty name");
                return;
            }
            else if (context.Categories.FirstOrDefault(c => c.Name == newCatName) != null
                && newCatName != oldCatName)
            {
                ErrorSuccessNotifier.AddErrorMessage("Category with this name already exist");
                return;
            }
            else
            {
                cat.Name = newCatName;
                context.SaveChanges();
                this.TextBoxCategoryTitle.Text = newCatName;
                this.DataBind();
                ErrorSuccessNotifier.AddSuccessMessage("Category Edited");
                this.TextBoxCategoryTitle.Text = cat.Name;
            }
        }

        protected void ButtonDeleteCategory_Click(object sender, EventArgs e)
        {
            int id = Convert.ToInt32(Request.QueryString["Id"]);
            var context = new ApplicationDbContext();
            var cat = context.Categories
                .Include("Questions").Include("Questions.Votes").Include("Questions.Answers")
                .Include("Questions.Answers").Include("Questions.Answers.Votes")
                .FirstOrDefault(c => c.Id == id);


            foreach (var question in cat.Questions)
            {
                foreach (var answer in question.Answers)
                {
                    context.AnswerVotes.RemoveRange(answer.Votes);
                }

                context.Answers.RemoveRange(question.Answers);
                context.QuestionVotes.RemoveRange(question.Votes);
            }

            context.Questions.RemoveRange(cat.Questions);
            context.Categories.Remove(cat);
            context.SaveChanges();

            ErrorSuccessNotifier.ShowAfterRedirect = true;
            ErrorSuccessNotifier.AddSuccessMessage("Category Deleted");
            this.Response.Redirect("~/Categories.aspx");
        }
    }
}