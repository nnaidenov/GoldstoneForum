using System.Collections.Generic;

namespace GoldstoneForum.Models
{
    public class Category
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public virtual ICollection<Question> Questions { get; set; }
        public Category()
        {
            this.Questions = new HashSet<Question>();
        }
    }
}