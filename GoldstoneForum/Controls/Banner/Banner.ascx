<%@ Control Language="C#" AutoEventWireup="true" CodeBehind="Banner.ascx.cs" Inherits="CustomControl.Banner" %>

<asp:HyperLink ID="HyperLinkBanner" NavigateUrl="navigateurl" runat="server">
    <asp:Image ID="ImageBanner"  imageurl="imageurl" runat="server"/>
</asp:HyperLink>