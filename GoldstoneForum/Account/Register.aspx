<%@ Page Title="Register" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Register.aspx.cs" Inherits="GoldstoneForum.Account.Register" %>

<asp:Content runat="server" ID="BodyContent" ContentPlaceHolderID="MainContent">
    <hgroup class="title">
        <h1><%: Title %>.</h1>
    </hgroup>
    <p class="text-error">
        <asp:Literal runat="server" ID="ErrorMessage" />
    </p>

    <fieldset class="form-horizontal">
        <legend>Create a new account.</legend>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="UserName" CssClass="control-label">User name</asp:Label>
            <div class="controls">
                <asp:TextBox runat="server" ID="UserName" MaxLength="16" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="UserName" Display="Dynamic"
                    CssClass="text-error" ErrorMessage="The user name field is required." />
                <asp:RegularExpressionValidator ID="RegularExpressionValidatorUsername" runat="server"
                    ControlToValidate="UserName" CssClass="text-error"
                    ErrorMessage="Invalid UserName!" Display="Dynamic"
                    ValidationExpression="[a-zA-Z][a-zA-Z0-9_]{6,16}" />
            </div>
        </div>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="Password" CssClass="control-label" >Password</asp:Label>
            <div class="controls">
                <asp:TextBox runat="server" ID="Password" TextMode="Password" MaxLength="16" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="Password"
                    CssClass="text-error" ErrorMessage="The password field is required." />
            </div>
        </div>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="ConfirmPassword" CssClass="control-label">Confirm password</asp:Label>
            <div class="controls">
                <asp:TextBox runat="server" ID="ConfirmPassword" TextMode="Password" MaxLength="16" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="ConfirmPassword"
                    CssClass="text-error" Display="Dynamic" ErrorMessage="The confirm password field is required." />
                <asp:CompareValidator runat="server" ControlToCompare="Password" ControlToValidate="ConfirmPassword"
                    CssClass="text-error" Display="Dynamic" ErrorMessage="The password and confirmation password do not match." />
            </div>
        </div>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="Email" CssClass="control-label">Email</asp:Label>
            <div class="controls">
                <asp:TextBox runat="server" ID="Email" TextMode="Email" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="Email"
                    CssClass="text-error" Display="Dynamic" ErrorMessage="The email is required!" />
            </div>
        </div>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="UploadAvatar" CssClass="control-label">Avatar</asp:Label>
            <div class="controls">
                <asp:FileUpload ID="UploadAvatar" runat="server" />
                <asp:Label runat="server" ID="StatusLabel" Text="Upload status: " />
                <asp:RegularExpressionValidator ID="uplValidator" runat="server" ControlToValidate="UploadAvatar" CssClass="text-error"
                    ErrorMessage=".JPG, .JPEG , .PNG &amp; GIF formats are allowed"
                    ValidationExpression="(.+\.([Gg][iI][fF])|.+\.([Jj][pP][Gg])|.+\.([Jj][Pp][Ee][Gg])|.+\.([Pp][Nn][Gg]))"></asp:RegularExpressionValidator>
            </div>
        </div>
        <div class="form-actions no-color">
            <asp:Button runat="server" OnClick="CreateUser_Click" Text="Register" CssClass="btn" />
        </div>

    </fieldset>

</asp:Content>
