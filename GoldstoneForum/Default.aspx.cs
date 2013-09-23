using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using GoldstoneForum.Models;

namespace GoldstoneForum
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var questions = context.Questions.OrderByDescending(q => q.DatePosted).Take(10);

            this.ListViewQuestions.DataSource = questions.ToList();
            this.ListViewQuestions.DataBind();
        }
    }
}