using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace GoldstoneForum.Models
{
    public class AnswerVotes
    {
        public int Id { get; set; }
        [Key]
        public virtual ApplicationUser User { get; set; }
        [Key]
        public virtual Answer Answers { get; set; }
    }
}