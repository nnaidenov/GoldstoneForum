<%@ Page Title="" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="EditAnswer.aspx.cs" Inherits="GoldstoneForum.EditAnswer" %>

<%@ Register TagPrefix="asp" Namespace="AjaxControlToolkit" Assembly="AjaxControlToolkit" %>

<asp:Content ID="Content1" ContentPlaceHolderID="MainContent" runat="server">

    <fieldset class="form-horizontal">

        <div class="control-group">
            <asp:Label runat="server" AssociatedControlID="AnswerText" CssClass="control-label">Answer</asp:Label>
            <div class="controls">
                <asp:TextBox ID="AnswerText" Height="250" TextMode="MultiLine" Width="500" runat="server" />
                <asp:HtmlEditorExtender
                    TargetControlID="AnswerText"
                    runat="server" EnableSanitization="false" />
                <asp:RequiredFieldValidator runat="server" ControlToValidate="AnswerText"
                    CssClass="text-error" ErrorMessage="Question body is required." />
            </div>
        </div>

        <div class="form-actions no-color">
            <asp:Button ID="ButtonEditAnswer" runat="server" OnClick="ButtonEditAnswer_Click" Text="Edit" CssClass="btn" />
        </div>

    </fieldset>

</asp:Content>
