using GoldstoneForum.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace GoldstoneForum
{
    public partial class SearchResults : System.Web.UI.Page
    {
        protected void Page_PreRender(object sender, EventArgs e)
        {
            var context = new ApplicationDbContext();
            var searchWords = Request.Params["q"];
            List<Question> results = new List<Question>();
            if (searchWords == null || searchWords.Length == 0)
            {
                results = context.Questions.OrderByDescending(t => t.DatePosted).ThenByDescending(t => t.Votes.Count).ToList();
            }
            else
            {
                var query = context.Questions.AsQueryable();
                var splitedWords = searchWords.Split(' ');
                foreach (var word in splitedWords)
                {
                    query = (
                        from q in query
                        where q.Title.Contains(word)
                        select q).AsQueryable();
                }

                results = query.ToList();
            }

            var newResult = results.Distinct();
            this.ListViewQuestions.DataSource = newResult.OrderByDescending(t => t.DatePosted).ThenByDescending(t => t.Votes.Count);
            this.DataBind();
        }
    }
}