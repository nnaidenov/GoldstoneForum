using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace GoldstoneForum.Models
{
    public class Question
    {
        public int Id { get; set; }
        public string Text { get; set; }
        public string Title { get; set; }
        public DateTime DatePosted { get; set; }
        public virtual ApplicationUser User { get; set; }
        public virtual Category Category { get; set; }
        public virtual ICollection<QuestionVotes> Votes { get; set; }
        public virtual ICollection<Answer> Answers { get; set; }

        public Question()
        {
            this.Answers = new HashSet<Answer>();
            this.Votes = new HashSet<QuestionVotes>();
        }
    }
}