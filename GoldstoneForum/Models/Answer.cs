using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace GoldstoneForum.Models
{
    public class Answer
    {
        public int Id { get; set; }
        public string Text { get; set; }
        public DateTime DatePosted { get; set; }
        public virtual ApplicationUser User { get; set; }
        public virtual ICollection<AnswerVotes> Votes { get; set; }

        public virtual Question Question { get; set; }

        public Answer()
        {
            this.Votes = new HashSet<AnswerVotes>();
        }
    }
}