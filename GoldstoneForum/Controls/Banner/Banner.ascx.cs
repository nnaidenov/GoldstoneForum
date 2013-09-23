using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace CustomControl
{
    public partial class Banner : System.Web.UI.UserControl
    {
        public string BannerGoUrl { get; set; }
        public string BannerImageUrl { get; set; }
        public string BannerAlt { get; set; }
        public string BannerTitle { get; set; }

        protected void Page_Load(object sender, EventArgs e)
        {
            this.HyperLinkBanner.NavigateUrl = this.BannerGoUrl;
            this.ImageBanner.ImageUrl = this.BannerImageUrl;
            this.ImageBanner.AlternateText = this.BannerAlt;
            this.ImageBanner.Attributes.Add("title", this.BannerTitle);
        }
    }
}