using GoldstoneForum.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GoldstoneForum
{
    public partial class Questions : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {

        }

        // The return type can be changed to IEnumerable, however to support
        // paging and sorting, the following parameters must be added:
        //     int maximumRows
        //     int startRowIndex
        //     out int totalRowCount
        //     string sortByExpression
        public IQueryable<GoldstoneForum.Models.Question> GridViewQuestions_GetData()
        {
            var context = new ApplicationDbContext();
            return context.Questions.OrderByDescending(q => q.DatePosted);
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


        protected bool CanUserVoteOnQuestion(int id)
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

        protected bool CanUserUnVoteOnQuestion(int id)
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }
            else
            {
                return !CanUserVoteOnQuestion(id);
            }
        }
    }
}