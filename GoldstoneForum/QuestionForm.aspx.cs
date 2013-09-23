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
    public partial class QuestionForm : System.Web.UI.Page
    {
        private int questionId;

        protected void Page_Load(object sender, EventArgs e)
        {
            if (!int.TryParse(this.Request.Params["id"], out this.questionId))
            {
                this.Response.Redirect("~/Default.aspx");
            }
        }

        protected void Page_PreRender(object sender, EventArgs e)
        {
            if (!User.Identity.IsAuthenticated || User.IsInRole("Banned"))
            {
                this.PanelEditorContainer.Visible = false;
            }
        }

        protected void ButtonEditQuestion_Command(object sender, CommandEventArgs e)
        {
            this.Response.Redirect("~/EditQuestion.aspx?id=" + this.questionId);
        }

        protected void ButtonEditAnswer_Command(object sender, CommandEventArgs e)
        {
            int answerId = Convert.ToInt32(e.CommandArgument);
            this.Response.Redirect("~/EditAnswer.aspx?id=" + answerId);
        }

        protected void ButtonHideQuestion_Command(object sender, CommandEventArgs e)
        {
            var context = new ApplicationDbContext();
            var question = context.Questions.Find(this.questionId);

            foreach (var answer in question.Answers)
            {
                context.AnswerVotes.RemoveRange(answer.Votes);
            }

            context.Answers.RemoveRange(question.Answers);
            context.QuestionVotes.RemoveRange(question.Votes);
            context.Questions.Remove(question);
            context.SaveChanges();

            ErrorSuccessNotifier.ShowAfterRedirect = true;
            ErrorSuccessNotifier.AddSuccessMessage("Question removed");
            Response.Redirect("~/Default.aspx", false);
        }

        protected void ButtonHideAnswer_Command(object sender, CommandEventArgs e)
        {
            int answerId = Convert.ToInt32(e.CommandArgument);
            var context = new ApplicationDbContext();
            var answer = context.Answers.Find(answerId);
            context.AnswerVotes.RemoveRange(answer.Votes);
            context.Answers.Remove(answer);
            context.SaveChanges();

            ErrorSuccessNotifier.AddSuccessMessage("Answer removed");
            this.DataBind();
        }

        protected bool CanUserVoteOnQuestion()
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }

            var context = new ApplicationDbContext();

            var question = context.Questions.Find(questionId);
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

        protected bool CanUserVoteOnAnswer(int answerId)
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }

            var context = new ApplicationDbContext();

            var answer = context.Answers.Find(answerId);
            var username = this.User.Identity.Name;
            var user = context.Users.FirstOrDefault(u => u.UserName == username);

            if (answer.Votes.Any(v => v.User == user))
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        protected bool CanUserUnVoteOnAnswer(int answerId)
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }
            else
            {
                return !CanUserVoteOnAnswer(answerId);
            }
        }

        protected bool CanUserUnVoteOnQuestion()
        {
            if (!this.User.Identity.IsAuthenticated)
            {
                return false;
            }
            else
            {
                return !CanUserVoteOnQuestion();
            }
        }

        protected bool CanUserEditOrRemoveQuestion()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return false;
            }

            var context = new ApplicationDbContext();

            var user = context.Users.FirstOrDefault(u => u.UserName == User.Identity.Name);

            bool isAuthor =
                context.Questions.Find(this.questionId).User == user;

            if (this.User.IsInRole("Admin") || isAuthor)
            {
                return true;
            }

            return false;
        }

        protected bool CanUserEditOrRemoveAnswer(int answerId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return false;
            }

            var context = new ApplicationDbContext();

            var user = context.Users.FirstOrDefault(u => u.UserName == User.Identity.Name);

            bool isAuthor =
                context.Answers.Find(answerId).User == user;

            if (this.User.IsInRole("Admin") || isAuthor)
            {
                return true;
            }

            return false;
        }

        protected void VoteOnQuestion_Command(object sender, CommandEventArgs e)
        {
            int id = this.questionId;
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

        protected void VoteOnAnswer_Command(object sender, CommandEventArgs e)
        {
            int id = Convert.ToInt32(e.CommandArgument);
            var context = new ApplicationDbContext();
            var answer = context.Answers.Find(id);
            var username = this.User.Identity.Name;
            var user = context.Users.FirstOrDefault(u => u.UserName == username);

            if (e.CommandName == "Vote")
            {
                answer.Votes.Add(new AnswerVotes() { User = user });
            }

            if (e.CommandName == "Unvote")
            {
                var vote = answer.Votes.FirstOrDefault(v => v.User == user);
                answer.Votes.Remove(vote);
            }

            context.SaveChanges();

            this.ListViewQuestionAnswers.DataBind();
        }

        // The id parameter should match the DataKeyNames value set on the control
        // or be decorated with a value provider attribute, e.g. [QueryString]int id
        public GoldstoneForum.Models.Question FormViewQuestion_GetItem()
        {
            var context = new ApplicationDbContext();
            return context.Questions.Find(this.questionId);
        }

        protected void PostAnswer_Click(object sender, EventArgs e)
        {
            var answerText = this.TextAnswer.Text;

            if (string.IsNullOrWhiteSpace(answerText))
            {
                ErrorSuccessNotifier.AddErrorMessage("Answer must have body");
                return;
            }

            var questionId = Convert.ToInt32(Request.Params["id"]);
            var user = this.User.Identity.Name;
            var context = new ApplicationDbContext();
            var dbUser = context.Users.FirstOrDefault(u => u.UserName == user);
            var dbQuestion = context.Questions.Find(questionId);

            var newAnswer = new Answer
            {
                Text = answerText,
                User = dbUser,
                Question = dbQuestion,
                DatePosted = DateTime.Now
            };

            context.Answers.Add(newAnswer);
            context.SaveChanges();

            ErrorSuccessNotifier.AddSuccessMessage("Added new answer");
            this.TextAnswer.Text = "";
            this.DataBind();
            //Response.Redirect("~/QuestionForm.aspx?id=" + questionId);
        }

        // The return type can be changed to IEnumerable, however to support
        // paging and sorting, the following parameters must be added:
        //     int maximumRows
        //     int startRowIndex
        //     out int totalRowCount
        //     string sortByExpression
        public IQueryable<GoldstoneForum.Models.Answer> ListViewQuestionAnswers_GetData()
        {
            var context = new ApplicationDbContext();
            return context.Answers.Where(a => a.Question.Id == questionId).OrderBy(a => a.DatePosted);
        }
    }
}