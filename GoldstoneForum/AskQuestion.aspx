<%@ Page Title="Ask a 
    "
    Language="C#" MasterPageFile="~/Site.Master"
    AutoEventWireup="true" CodeBehind="AskQuestion.aspx.cs"
    Inherits="GoldstoneForum.AskQuestion" %>

<%@ Register TagPrefix="asp" Namespace="AjaxControlToolkit" Assembly="AjaxControlToolkit" %>

<asp:Content ID="Content1" ContentPlaceHolderID="MainContent" runat="server">

    <fieldset class="form-horizontal">
        <legend>Ask a question.</legend>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="TextBoxTitle" CssClass="control-label">Title</asp:Label>
            <div class="controls">
                <asp:TextBox runat="server" ID="TextBoxTitle" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="TextBoxTitle"
                    CssClass="text-error" ErrorMessage="The question title is required." />
            </div>
        </div>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="DropDownListCategories" CssClass="control-label">Category</asp:Label>
            <div class="controls">
                <asp:DropDownList runat="server" ID="DropDownListCategories"
                    DataTextField="Name"
                    DataValueField="Id">
                </asp:DropDownList>
            </div>
        </div>
        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="QuestionText" CssClass="control-label">Question</asp:Label>
            <div class="controls">
                <asp:TextBox ID="QuestionText" Height="250" TextMode="MultiLine" Width="500" runat="server" />
                <asp:HtmlEditorExtender
                    TargetControlID="QuestionText"
                    runat="server" EnableSanitization="false" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="QuestionText"
                    CssClass="text-error" ErrorMessage="Question body is required." />
            </div>
        </div>

        <div class="form-actions no-color">
            <asp:Button ID="AskQUestion" runat="server" OnClick="AskQUestion_Click" Text="Post" CssClass="btn" />
        </div>

    </fieldset>

</asp:Content>
