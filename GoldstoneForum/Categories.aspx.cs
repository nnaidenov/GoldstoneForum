using GoldstoneForum.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using GoldstoneForum.Models;
using System.Web.UI.HtmlControls;
using Error_Handler_Control;

namespace GoldstoneForum
{
    public partial class Categories : System.Web.UI.Page
    {
        protected void Page_PreRender(object sender, EventArgs e)
        {
            if (this.CanAddCategory())
            {
                this.PanelAddCategory.Visible = true;
            }
        }


        public IQueryable<GoldstoneForum.Models.Category> GridViewCategories_GetData()
        {
            var context = new ApplicationDbContext();
            return context.Categories;
        }

        protected bool HasLastQuestion(int id)
        {
            var context = new ApplicationDbContext();
            var cat = context.Categories.Find(id);

            if (cat.Questions != null && cat.Questions.Count > 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        protected string GetLastQuestionTitle(int id)
        {
            var context = new ApplicationDbContext();
            var cat = context.Categories.Find(id);

            var question = cat.Questions.OrderByDescending(q => q.DatePosted).FirstOrDefault();

            if (question == null)
            {
                return "";
            }
            else
            {
                return question.Title;
            }
        }

        protected string GetLastQuestionUrl(int id)
        {
            var context = new ApplicationDbContext();
            var cat = context.Categories.Find(id);

            var question = cat.Questions.OrderByDescending(q => q.DatePosted).FirstOrDefault();

            if (question == null)
            {
                return "";
            }
            else
            {
                return "~/QuestionForm.aspx?id=" + question.Id;
            }
        }

        protected bool CanAddCategory()
        {
            if (User.Identity.IsAuthenticated && User.IsInRole("Admin"))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        protected void ButtonAddCategory_Click(object sender, EventArgs e)
        {
            if (!CanAddCategory())
            {
                ErrorSuccessNotifier.AddWarningMessage("Only admins can add categories");
                return;
            }

            var context = new ApplicationDbContext();

            string newCatName = this.TextBoxNewCategory.Text;

            if (string.IsNullOrWhiteSpace(newCatName))
            {
                ErrorSuccessNotifier.AddErrorMessage("Please enter category name");
                return;
            }
            else if (context.Categories.FirstOrDefault(c => c.Name == newCatName) != null)
            {
                ErrorSuccessNotifier.AddErrorMessage("Category with this name already exist");
                return;
            }
            else
            {
                Models.Category cat = new Models.Category() { Name = newCatName };
                context.Categories.Add(cat);
                context.SaveChanges();
                this.TextBoxNewCategory.Text = "";
                this.DataBind();
                ErrorSuccessNotifier.AddSuccessMessage("Category added");
            }
        }
    }
}