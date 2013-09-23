<%@ Page Title="" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="EditUser.aspx.cs" Inherits="GoldstoneForum.Admin.EditUser" %>

<asp:Content ID="ContentEditUser" ContentPlaceHolderID="MainContent" runat="server">
    <asp:LinkButton ID="LinkButtonReturn" runat="server" CssClass="btn btn-default" 
        Text="Back" OnClick="LinkButtonReturn_Click" />
    <h2>Edit User</h2>
    <div class="form-group">
        <label for="LabelUserName">UsreName:</label>    
        <asp:TextBox ID="TextBoxUserName" runat="server" MaxLength="16" CssClass="form-control"/>
        <asp:RequiredFieldValidator runat="server" ControlToValidate="TextBoxUserName" Display="Dynamic"
            CssClass="text-error" ErrorMessage="The user name field is required." />
        <asp:RegularExpressionValidator ID="RegularExpressionValidatorUsername" runat="server"
            ControlToValidate="TextBoxUserName" CssClass="text-error"
            ErrorMessage="Invalid UserName!" Display="Dynamic"
            ValidationExpression="[a-zA-Z][a-zA-Z0-9_]{6,16}" />

        <br />
    </div>
    <div class="form-group">
        <label for="exampleInputPassword1">Email:</label>
            
        <asp:TextBox ID="TextBoxEmail" runat="server" TextMode="Email" CssClass="form-control" />
        <asp:RequiredFieldValidator runat="server" ControlToValidate="TextBoxEmail"
            CssClass="text-error" Display="Dynamic" ErrorMessage="The email is required!" />
        <asp:RegularExpressionValidator ID="RegularExpressionValidatorEmail" runat="server"
            ErrorMessage="Email address is incorrect!" ControlToValidate="TextBoxEmail" CssClass="text-error"
            ValidationExpression="\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*" />

    </div>
    <br />
    Avatar:<asp:FileUpload ID="UploadAvatar" runat="server" />
    <asp:RegularExpressionValidator ID="uplValidator" runat="server" ControlToValidate="UploadAvatar" CssClass="text-error"
        ErrorMessage=".JPG, .JPEG , PNG &amp; GIF formats are allowed"
        ValidationExpression="(.+\.([Gg][iI][fF])|.+\.([Jj][pP][Gg])|.+\.([Pp][Nn][Gg])|.+\.([Jj][Pp][Ee][Gg]))" />
    <br /><br />
    <asp:LinkButton ID="LinkButtonSaveUser" runat="server" CssClass="btn btn-default"
        Text="Save Changes" OnClick="LinkButtonSaveUser_Click" />
    <br /><br />
    <div class="btn-group">
    <asp:Button ID="ButtonBAN" runat="server" Text="BAN User" CssClass="btn btn-default" 
        OnClientClick="return confirm('Do you want to Ban user ?');"
        OnClick="ButtonBAN_Click" />
    <asp:Button ID="ButtonAdmin" runat="server" Text="Add Admin" CssClass="btn btn-default" 
        OnClientClick="return confirm('Do you want to create admin?');"
        OnClick="ButtonAdmin_Click" />
        </div>
</asp:Content>

