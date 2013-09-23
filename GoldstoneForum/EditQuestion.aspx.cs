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
    public partial class EditQuestion : System.Web.UI.Page
    {
        private int questionId;
        protected bool CanUserEditQuestion()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return false;
            }

            var context = new ApplicationDbContext();

            var user = context.Users.FirstOrDefault(u => u.UserName == User.Identity.Name);
            var questionId = Convert.ToInt32(Request.Params["id"]);
            bool isAuthor =
                context.Questions.Find(questionId).User == user;

            if (this.User.IsInRole("Admin") || isAuthor)
            {
                return true;
            }

            return false;
        }
        protected void Page_Load(object sender, EventArgs e)
        {
            if (!int.TryParse(this.Request.Params["id"], out this.questionId))
            {
                this.Response.Redirect("~/Default.aspx");
            }

            if (!CanUserEditQuestion())
            {
                this.Response.Redirect("~/Default.aspx");
            }
        }

        protected void Page_PreRender(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var questionId = Convert.ToInt32(Request.Params["id"]);
            var categories = context.Categories.ToList();
            var question = context.Questions.Find(questionId);
            string qCat = question.Category.Name;
            this.TextBoxTitle.Text = question.Title;
            this.QuestionText.Text = question.Text;
            this.DropDownListCategories.DataSource = categories;
            var dropDownCategories = this.DropDownListCategories.Items;

            this.DataBind();

            foreach (ListItem dropDownCategory in dropDownCategories)
            {
                if (dropDownCategory.Text == qCat)
                {
                    dropDownCategory.Selected = true;
                    return;
                }
            }
        }

        protected void ButtonEditQuestion_Click(object sender, EventArgs e)
        {
            var title = this.TextBoxTitle.Text;
            var questText = this.QuestionText.Text;

            if (string.IsNullOrWhiteSpace(title))
            {
                ErrorSuccessNotifier.AddErrorMessage("Question title can't be empty");
                return;
            }

            if (string.IsNullOrWhiteSpace(questText) || questText == "<br>")
            {
                ErrorSuccessNotifier.AddErrorMessage("Question body can't be empty");
                return;
            }

            var questionId = Convert.ToInt32(Request.Params["id"]);
            var context = new ApplicationDbContext();
            var question = context.Questions.Find(questionId);
            int categoryId = Convert.ToInt32(this.DropDownListCategories.SelectedItem.Value);
            var category = context.Categories.Find(categoryId);

            if (question.Title != title)
            {
                question.Title = title;
            }

            if (question.Text != questText)
            {
                question.Text = questText;
            }

            if (question.Category != category)
            {
                question.Category = category;
            }

            context.SaveChanges();

            ErrorSuccessNotifier.ShowAfterRedirect = true;
            ErrorSuccessNotifier.AddSuccessMessage("Question edited");

            Response.Redirect("~/QuestionForm.aspx?id=" + questionId);
        }
    }
}